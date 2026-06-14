package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/discovery"
	"github.com/Su1ph3r/nubicustos/internal/preflight"
	gcpprovider "github.com/Su1ph3r/nubicustos/internal/providers/gcp"
)

type preflightFlags struct {
	provider      string
	profile       string
	region        string
	mfaSerial     string
	mfaToken      string
	ssoLogin      bool
	nonInteract   bool
	tools         []string
	format        string
	noProbe       bool
	writePolicies string
	org           bool

	// Azure
	authMethod   string
	tenantID     string
	clientID     string
	clientSecret string
	subscription string

	// GCP / Kubernetes
	project    string
	k8sContext string
}

func newPreflightCmd() *cobra.Command {
	f := &preflightFlags{}
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Check whether a credential has the access each scanning tool needs",
		Long: "Verify, read-only and before any scan, that the identity behind a\n" +
			"credential holds the permissions Nubicustos's own checks and the optional\n" +
			"external tools (Prowler, ScoutSuite, CloudSploit) require. Leads with IAM\n" +
			"policy simulation for exact per-action allow/deny and cross-checks with a\n" +
			"thin live read-probe (catching SCP/boundary denials simulation cannot see).\n" +
			"Reports exactly what is missing and emits an attachable least-privilege\n" +
			"policy to grant it — suitable to hand to a client team.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPreflight(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.provider, "provider", "aws", "cloud provider: aws | azure | gcp | k8s")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile")
	pf.StringVar(&f.region, "region", "", "AWS region for the session")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` automatically if the SSO session is expired")
	pf.BoolVar(&f.nonInteract, "non-interactive", false, "never prompt; fail fast if MFA input is required")
	pf.StringSliceVar(&f.tools, "tools", nil, "tools to check by key (default: all; e.g. nubicustos,prowler)")
	pf.StringVar(&f.format, "format", "text", "output format: text | json")
	pf.BoolVar(&f.noProbe, "no-probe", false, "skip the live read-probe cross-check (simulation only)")
	pf.StringVar(&f.writePolicies, "write-policies", "", "directory to write a remediation policy/role JSON per non-ready tool")
	pf.BoolVar(&f.org, "org", false, "AWS: also verify org-wide scan access (Organizations enumeration + member assume-role) for the native checks")

	pf.StringVar(&f.authMethod, "auth", "", "Azure auth: auto | cli | interactive-browser | device-code | service-principal | managed-identity")
	pf.StringVar(&f.tenantID, "tenant", "", "Azure tenant id (service-principal)")
	pf.StringVar(&f.clientID, "client-id", "", "Azure client id (service-principal)")
	pf.StringVar(&f.clientSecret, "client-secret", "", "Azure client secret (service-principal)")
	pf.StringVar(&f.subscription, "subscription", "", "Azure subscription to probe (default: first enabled subscription)")

	pf.StringVar(&f.project, "project", "", "GCP project to check (default: first active project)")
	pf.StringVar(&f.k8sContext, "context", "", "Kubernetes context to check (default: current context)")
	return cmd
}

func runPreflight(ctx context.Context, f *preflightFlags) error {
	switch strings.ToLower(f.provider) {
	case "aws":
		return runPreflightAWS(ctx, f)
	case "azure":
		return runPreflightAzure(ctx, f)
	case "gcp":
		return runPreflightGCP(ctx, f)
	case "k8s":
		return runPreflightK8s(ctx, f)
	default:
		return fmt.Errorf("preflight supports --provider aws | azure | gcp | k8s")
	}
}

func runPreflightAWS(ctx context.Context, f *preflightFlags) error {
	// Validate the tool selection before authenticating, so a typo fails fast
	// without resolving credentials.
	tools, err := selectTools(f.tools, f.org)
	if err != nil {
		return err
	}

	prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteract)
	cfg, ident, path, err := auth.ResolveAWS(ctx, auth.AWSOptions{
		Profile:       f.profile,
		Region:        f.region,
		MFASerial:     f.mfaSerial,
		MFAToken:      f.mfaToken,
		AllowSSOLogin: f.ssoLogin,
	}, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)

	opts := preflight.Options{
		Provider:  "aws",
		Identity:  ident.ARN,
		Account:   ident.Account,
		Tools:     tools,
		Simulator: iam.NewFromConfig(cfg),
	}
	if !f.noProbe {
		opts.Prober = preflight.NewAWSProber(cfg)
	}
	return emitPreflight(ctx, f, opts)
}

// runPreflightAzure verifies Azure RBAC access for the native checks. Azure is
// probe-only: a live read is itself authoritative for access (it reflects deny
// assignments and Azure Policy), so the prober is the sole source and the Azure
// remediator renders gaps as a custom role definition.
func runPreflightAzure(ctx context.Context, f *preflightFlags) error {
	tools, err := selectAzureTools(f.tools)
	if err != nil {
		return err
	}

	prompter := auth.NewCLIPrompter("", !f.nonInteract)
	cred, err := auth.ResolveAzure(ctx, auth.AzureOptions{
		Method:       auth.AzureMethod(f.authMethod),
		TenantID:     f.tenantID,
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
	}, prompter)
	if err != nil {
		return err
	}

	// Resolve a subscription to probe resource-level reads against.
	sub := f.subscription
	if sub == "" {
		disc, derr := discovery.AzureSubscriptions(ctx, cred, discovery.AzureOptions{})
		if derr != nil {
			return fmt.Errorf("resolving a subscription to probe: %w", derr)
		}
		if len(disc.Subscriptions) == 0 {
			return fmt.Errorf("no enabled subscription visible to this identity (use --subscription)")
		}
		sub = disc.Subscriptions[0].ID
	}
	fmt.Fprintf(os.Stderr, "authenticated to Azure; checking access against subscription %s\n", sub)

	opts := preflight.Options{
		Provider:   "azure",
		Identity:   "Azure credential",
		Account:    sub,
		Tools:      tools,
		Prober:     preflight.NewAzureProber(cred, sub),
		Remediator: preflight.NewAzureRemediator(sub),
	}
	return emitPreflight(ctx, f, opts)
}

// runPreflightGCP verifies GCP IAM access for the native checks against a
// project. It uses Resource Manager's TestIamPermissions — GCP's authoritative
// "which of these can I do" API — so the check is probe-only and the GCP
// remediator renders gaps as a custom role definition.
func runPreflightGCP(ctx context.Context, f *preflightFlags) error {
	tools, err := selectGCPTools(f.tools)
	if err != nil {
		return err
	}

	creds, err := auth.ResolveGCP(ctx)
	if err != nil {
		return err
	}
	project := f.project
	if project == "" {
		projects, derr := gcpprovider.EnabledProjects(ctx, creds)
		if derr != nil {
			return fmt.Errorf("resolving a project to check: %w", derr)
		}
		if len(projects) == 0 {
			return fmt.Errorf("no active project visible to this identity (use --project)")
		}
		project = projects[0]
	}
	fmt.Fprintf(os.Stderr, "authenticated to GCP; checking access against project %s\n", project)

	opts := preflight.Options{
		Provider:   "gcp",
		Identity:   "GCP credential",
		Account:    project,
		Tools:      tools,
		Prober:     preflight.NewGCPProber(ctx, creds, project),
		Remediator: preflight.NewGCPRemediator(project),
	}
	return emitPreflight(ctx, f, opts)
}

// runPreflightK8s verifies Kubernetes RBAC access for the native checks against
// one context. It uses SelfSubjectAccessReview — the canonical "can-i" API — so
// the check is probe-only and the K8s remediator renders gaps as a ClusterRole.
func runPreflightK8s(ctx context.Context, f *preflightFlags) error {
	tools, err := selectK8sTools(f.tools)
	if err != nil {
		return err
	}

	var contexts []string
	if f.k8sContext != "" {
		contexts = []string{f.k8sContext}
	}
	clusters, err := auth.ResolveK8s(contexts)
	if err != nil {
		return err
	}
	cluster := clusters[0] // check one context; --context selects it
	fmt.Fprintf(os.Stderr, "checking Kubernetes access against context %s\n", cluster.Context)

	prober, err := preflight.NewK8sProber(cluster.Config)
	if err != nil {
		return fmt.Errorf("building Kubernetes client: %w", err)
	}
	opts := preflight.Options{
		Provider:   "k8s",
		Identity:   "Kubernetes credential",
		Account:    cluster.Context,
		Tools:      tools,
		Prober:     prober,
		Remediator: preflight.NewK8sRemediator(),
	}
	return emitPreflight(ctx, f, opts)
}

// emitPreflight evaluates, optionally writes remediation files, renders the
// report, and gates the exit code — shared across providers.
func emitPreflight(ctx context.Context, f *preflightFlags, opts preflight.Options) error {
	rep := preflight.Evaluate(ctx, opts)

	if f.writePolicies != "" {
		if err := writeRemediationPolicies(f.writePolicies, rep); err != nil {
			return err
		}
	}

	if f.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printPreflight(os.Stdout, rep)
	}

	// Non-zero exit when access is not fully ready, so the check can gate a pipeline.
	if rep.Overall != preflight.ReadinessReady {
		return fmt.Errorf("preflight: overall access is %s (see report above)", rep.Overall)
	}
	return nil
}

// selectAzureTools returns the requested Azure catalog tools (all if keys empty).
func selectAzureTools(keys []string) ([]preflight.Tool, error) {
	return selectProviderTools(keys, "Azure", preflight.AzureTools, preflight.AzureToolByKey)
}

// selectGCPTools returns the requested GCP catalog tools (all if keys empty).
func selectGCPTools(keys []string) ([]preflight.Tool, error) {
	return selectProviderTools(keys, "GCP", preflight.GCPTools, preflight.GCPToolByKey)
}

// selectK8sTools returns the requested Kubernetes catalog tools (all if keys empty).
func selectK8sTools(keys []string) ([]preflight.Tool, error) {
	return selectProviderTools(keys, "Kubernetes", preflight.K8sTools, preflight.K8sToolByKey)
}

// selectProviderTools resolves a tool selection against a single-provider catalog
// that has no external tools (Azure/GCP/K8s — only the native engine today).
func selectProviderTools(keys []string, label string, all []preflight.Tool, byKey func(string) (preflight.Tool, bool)) ([]preflight.Tool, error) {
	if len(keys) == 0 {
		return all, nil
	}
	var out []preflight.Tool
	for _, k := range keys {
		t, ok := byKey(strings.TrimSpace(k))
		if !ok {
			return nil, fmt.Errorf("unknown %s tool %q (known: nubicustos)", label, k)
		}
		out = append(out, t)
	}
	return out, nil
}

// selectTools returns the requested catalog tools (all if keys is empty). When
// org is set, the native Nubicustos entry also carries the org-wide-scan actions.
func selectTools(keys []string, org bool) ([]preflight.Tool, error) {
	if len(keys) == 0 {
		out := make([]preflight.Tool, 0, len(preflight.AWSTools))
		for _, t := range preflight.AWSTools {
			out = append(out, preflight.AWSToolWithOrg(t, org))
		}
		return out, nil
	}
	var out []preflight.Tool
	for _, k := range keys {
		t, ok := preflight.AWSToolByKey(strings.TrimSpace(k))
		if !ok {
			return nil, fmt.Errorf("unknown tool %q (known: nubicustos, prowler, scoutsuite, cloudsploit)", k)
		}
		out = append(out, preflight.AWSToolWithOrg(t, org))
	}
	return out, nil
}

func printPreflight(w *os.File, rep preflight.Report) {
	fmt.Fprintf(w, "PREFLIGHT — %s · account %s · %s\n", rep.Provider, rep.Account, rep.Identity)
	fmt.Fprintf(w, "method: %s\n\n", rep.Method)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, t := range rep.Tools {
		fmt.Fprintf(tw, "[%s]\t%s\t%d/%d permission(s)\n",
			strings.ToUpper(string(t.Readiness)), t.Name, len(t.Allowed), len(t.Actions))
	}
	tw.Flush()
	fmt.Fprintf(w, "\nOVERALL: %s\n", strings.ToUpper(string(rep.Overall)))

	for _, t := range rep.Tools {
		if t.Readiness == preflight.ReadinessReady {
			continue
		}
		fmt.Fprintf(w, "\n%s — %s\n", t.Name, t.Remediate.Summary)
		if len(t.Denied) > 0 {
			fmt.Fprintf(w, "  missing: %s\n", strings.Join(t.Denied, ", "))
		}
		if len(t.Conflicts) > 0 {
			fmt.Fprintf(w, "  runtime-blocked (SCP/boundary): %s\n", strings.Join(t.Conflicts, ", "))
		}
		if len(t.Unknown) > 0 {
			fmt.Fprintf(w, "  undetermined: %s\n", strings.Join(t.Unknown, ", "))
		}
	}
}

// writeRemediationPolicies writes one <key>.policy.json per non-ready tool.
func writeRemediationPolicies(dir string, rep preflight.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating policy dir: %w", err)
	}
	for _, t := range rep.Tools {
		if t.Remediate.PolicyDocument == "" {
			continue
		}
		p := filepath.Join(dir, t.Key+".policy.json")
		if err := os.WriteFile(p, []byte(t.Remediate.PolicyDocument), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", p, err)
		}
		fmt.Fprintf(os.Stderr, "wrote remediation policy for %s → %s\n", t.Name, p)
	}
	return nil
}
