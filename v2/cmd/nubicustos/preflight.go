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
	"github.com/Su1ph3r/nubicustos/internal/preflight"
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
	pf.StringVar(&f.provider, "provider", "aws", "cloud provider (aws)")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile")
	pf.StringVar(&f.region, "region", "", "AWS region for the session")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` automatically if the SSO session is expired")
	pf.BoolVar(&f.nonInteract, "non-interactive", false, "never prompt; fail fast if MFA input is required")
	pf.StringSliceVar(&f.tools, "tools", nil, "tools to check by key (default: all; e.g. nubicustos,prowler)")
	pf.StringVar(&f.format, "format", "text", "output format: text | json")
	pf.BoolVar(&f.noProbe, "no-probe", false, "skip the live read-probe cross-check (simulation only)")
	pf.StringVar(&f.writePolicies, "write-policies", "", "directory to write a remediation policy JSON per non-ready tool")
	pf.BoolVar(&f.org, "org", false, "also verify org-wide scan access (Organizations enumeration + member assume-role) for the native checks")
	return cmd
}

func runPreflight(ctx context.Context, f *preflightFlags) error {
	if strings.ToLower(f.provider) != "aws" {
		return fmt.Errorf("preflight currently supports --provider aws")
	}

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
