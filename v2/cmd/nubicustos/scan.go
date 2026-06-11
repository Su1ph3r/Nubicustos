package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	ruleschecks "github.com/Su1ph3r/nubicustos/internal/checks/rules"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/export"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	awsprovider "github.com/Su1ph3r/nubicustos/internal/providers/aws"
	azureprovider "github.com/Su1ph3r/nubicustos/internal/providers/azure"
	gcpprovider "github.com/Su1ph3r/nubicustos/internal/providers/gcp"
	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/validate"
)

type scanFlags struct {
	provider       string
	profile        string
	regions        []string
	mfaSerial      string
	mfaToken       string
	ssoLogin       bool
	sessionDur     time.Duration
	nonInteractive bool

	// Azure
	authMethod    string
	tenantID      string
	clientID      string
	clientSecret  string
	subscriptions []string

	// GCP
	projects []string

	// Kubernetes
	contexts []string

	dbPath     string
	exportPath string
	validate   bool
	rulesDir   string
}

func newScanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a cloud account for misconfigurations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.provider, "provider", "", "cloud provider: aws | azure | gcp | k8s (required)")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile")
	pf.StringSliceVar(&f.regions, "region", nil, "region(s) to scan (repeatable)")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN (for static-keys + MFA-condition profiles)")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` automatically if the SSO session is expired")
	pf.DurationVar(&f.sessionDur, "session-duration", 0, "temp-credential lifetime (e.g. 8h); default 12h")
	pf.BoolVar(&f.nonInteractive, "non-interactive", false, "never prompt; fail fast if MFA input is required")

	pf.StringVar(&f.authMethod, "auth", "", "Azure auth: auto | cli | interactive-browser | device-code | service-principal | managed-identity")
	pf.StringVar(&f.tenantID, "tenant", "", "Azure tenant id (service-principal)")
	pf.StringVar(&f.clientID, "client-id", "", "Azure client id (service-principal)")
	pf.StringVar(&f.clientSecret, "client-secret", "", "Azure client secret (service-principal)")
	pf.StringSliceVar(&f.subscriptions, "subscription", nil, "Azure subscription id(s) to scan (repeatable; default: all enabled)")
	pf.StringSliceVar(&f.projects, "project", nil, "GCP project id(s) to scan (repeatable; default: all active)")
	pf.StringSliceVar(&f.contexts, "context", nil, "Kubernetes context(s) to scan (repeatable; default: current context)")

	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.exportPath, "export", "", "write Cairn-format findings JSON to this path")
	pf.BoolVar(&f.validate, "validate", false, "opt-in: actively (read-only) confirm findings and capture evidence")
	pf.StringVar(&f.rulesDir, "rules-dir", "", "directory of user policy-as-code rules to evaluate alongside the built-ins")

	return cmd
}

func runScan(ctx context.Context, f *scanFlags) error {
	provider := strings.ToLower(f.provider)
	if provider == "" {
		return fmt.Errorf("--provider is required (aws | azure | gcp | k8s)")
	}

	prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteractive)

	sc := &engine.ScanContext{Ctx: ctx, Provider: provider, Regions: f.regions}
	var account, identity string

	switch provider {
	case "aws":
		cfg, ident, path, err := auth.ResolveAWS(ctx, auth.AWSOptions{
			Profile:         f.profile,
			Region:          firstRegion(f.regions),
			MFASerial:       f.mfaSerial,
			MFAToken:        f.mfaToken,
			SessionDuration: f.sessionDur,
			AllowSSOLogin:   f.ssoLogin,
		}, prompter)
		if err != nil {
			return err
		}
		sc.AWS = cfg
		sc.Account = ident.Account
		account, identity = ident.Account, ident.ARN
		fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)

		// Resolve regions once, up front, so regional collectors fan out cleanly.
		if len(sc.Regions) == 0 {
			if regs, rerr := awsprovider.EnabledRegions(ctx, cfg); rerr == nil && len(regs) > 0 {
				sc.Regions = regs
			} else {
				sc.Regions = []string{cfg.Region}
			}
		}
		fmt.Fprintf(os.Stderr, "scanning %d region(s)\n", len(sc.Regions))

	case "azure":
		cred, err := auth.ResolveAzure(ctx, auth.AzureOptions{
			Method:       auth.AzureMethod(f.authMethod),
			TenantID:     f.tenantID,
			ClientID:     f.clientID,
			ClientSecret: f.clientSecret,
		}, prompter)
		if err != nil {
			return err
		}

		// Discover the subscriptions in scope (§9.4), or honor an explicit list.
		subs := f.subscriptions
		if len(subs) == 0 {
			subs, err = azureprovider.EnabledSubscriptions(ctx, cred)
			if err != nil {
				return fmt.Errorf("enumerating subscriptions: %w", err)
			}
		}
		if len(subs) == 0 {
			return fmt.Errorf("no enabled Azure subscriptions visible to this identity (use --subscription to specify one)")
		}
		sc.Azure = engine.AzureSession{Credential: cred, Subscriptions: subs}
		sc.Account = strings.Join(subs, ",")
		account = sc.Account
		fmt.Fprintf(os.Stderr, "authenticated to Azure; scanning %d subscription(s)\n", len(subs))

	case "gcp":
		creds, err := auth.ResolveGCP(ctx)
		if err != nil {
			return err
		}
		projects := f.projects
		if len(projects) == 0 {
			projects, err = gcpprovider.EnabledProjects(ctx, creds)
			if err != nil {
				return fmt.Errorf("enumerating projects: %w", err)
			}
		}
		if len(projects) == 0 {
			return fmt.Errorf("no active GCP projects visible to this identity (use --project to specify one)")
		}
		sc.GCP = engine.GCPSession{Credentials: creds, Projects: projects}
		sc.Account = strings.Join(projects, ",")
		account = sc.Account
		fmt.Fprintf(os.Stderr, "authenticated to GCP; scanning %d project(s)\n", len(projects))

	case "k8s":
		clusters, err := auth.ResolveK8s(f.contexts)
		if err != nil {
			return err
		}
		ctxNames := make([]string, len(clusters))
		engineClusters := make([]engine.K8sCluster, len(clusters))
		for i, c := range clusters {
			ctxNames[i] = c.Context
			engineClusters[i] = engine.K8sCluster{Context: c.Context, Config: c.Config}
		}
		sc.K8s = engine.K8sSession{Clusters: engineClusters}
		sc.Account = strings.Join(ctxNames, ",")
		account = sc.Account
		fmt.Fprintf(os.Stderr, "authenticated to Kubernetes; scanning %d context(s)\n", len(clusters))

	default:
		return fmt.Errorf("unsupported provider %q", provider)
	}

	// Load any user-supplied policy-as-code rules for the rules engine to pick up.
	ruleschecks.SetUserRulesDir(f.rulesDir)

	started := time.Now().UTC()
	result := engine.Run(sc)

	// Opt-in active validation (read-only): confirm findings and attach evidence
	// before persistence so it is stored and exported. Off unless --validate.
	if f.validate {
		var venv validate.Env
		if provider == "aws" {
			cfg := sc.AWS // authenticated, MFA-satisfied scan session
			venv.EC2SnapshotAttr = func(region string) validate.EC2SnapshotAttrAPI {
				return ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })
			}
			venv.EC2ImageAttr = func(region string) validate.EC2ImageAttrAPI {
				return ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })
			}
			venv.RDSSnapshotAttr = func(region string) validate.RDSSnapshotAttrAPI {
				return rds.NewFromConfig(cfg, func(o *rds.Options) { o.Region = region })
			}
		}
		rep := validate.Run(ctx, result.Findings, validate.Options{Env: venv})
		fmt.Fprintf(os.Stderr, "validation: %d confirmed of %d attempted\n", rep.Confirmed, rep.Attempted)
		for _, e := range rep.Errors {
			fmt.Fprintf(os.Stderr, "  validation error: %v\n", e)
		}
	}

	finished := time.Now().UTC()

	// Persist.
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID := newScanID()
	if err := st.CreateScan(ctx, scanID, provider, account, identity, started); err != nil {
		return err
	}
	if err := st.SaveFindings(ctx, scanID, result.Findings, finished); err != nil {
		return err
	}
	if err := st.SaveGraph(ctx, scanID, result.Graph); err != nil {
		return err
	}

	// Optional Cairn export.
	if f.exportPath != "" {
		out, err := os.Create(f.exportPath)
		if err != nil {
			return fmt.Errorf("creating export file: %w", err)
		}
		defer out.Close()
		if err := export.Cairn(out, provider, account, result.Findings, finished); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "exported %d findings to %s\n", len(result.Findings), f.exportPath)
	}

	printSummary(result, scanID)
	return nil
}

// firstRegion returns the first region or "" — STS/global resolution only needs one.
func firstRegion(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	return regions[0]
}

// newScanID returns a sortable, collision-resistant scan id.
func newScanID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "scan-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func printSummary(r *engine.Result, scanID string) {
	counts := map[findings.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	paths := 0
	if r.Graph != nil {
		paths = len(r.Graph.Paths)
	}
	fmt.Printf("\nScan %s — %d findings, %d attack path(s) (%d collectors, %d checks)\n",
		scanID, len(r.Findings), paths, r.Collectors, r.Checks)
	// Surface collection/check failures on the stdout headline too — a result is
	// not "clean" if part of the scan failed; an error count buried only on
	// stderr can read as a green scan in captured output.
	if n := len(r.Errors); n > 0 {
		fmt.Printf("  ⚠ %d non-fatal error(s) — results may be incomplete (see stderr)\n", n)
	}
	for _, sev := range []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow, findings.SeverityInfo,
	} {
		if counts[sev] > 0 {
			fmt.Printf("  %-8s %d\n", sev, counts[sev])
		}
	}
	for _, f := range r.Findings {
		scope := f.Resource.ID
		if n := len(f.Affected); n > 0 {
			scope = fmt.Sprintf("%d affected", n)
		}
		fmt.Printf("  [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Title, scope)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d non-fatal error(s) during scan:\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", e)
		}
	}
}
