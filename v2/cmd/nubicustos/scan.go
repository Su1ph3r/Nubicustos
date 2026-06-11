package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/export"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	awsprovider "github.com/Su1ph3r/nubicustos/internal/providers/aws"
	"github.com/Su1ph3r/nubicustos/internal/store"
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
	authMethod   string
	tenantID     string
	clientID     string
	clientSecret string

	dbPath     string
	exportPath string
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
	pf.StringVar(&f.provider, "provider", "", "cloud provider: aws | azure (required)")
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

	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.exportPath, "export", "", "write Cairn-format findings JSON to this path")

	return cmd
}

func runScan(ctx context.Context, f *scanFlags) error {
	provider := strings.ToLower(f.provider)
	if provider == "" {
		return fmt.Errorf("--provider is required (aws | azure)")
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
		if _, err := auth.ResolveAzure(ctx, auth.AzureOptions{
			Method:       auth.AzureMethod(f.authMethod),
			TenantID:     f.tenantID,
			ClientID:     f.clientID,
			ClientSecret: f.clientSecret,
		}, prompter); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "authenticated to Azure (native Azure checks land in a later phase)")

	default:
		return fmt.Errorf("unsupported provider %q", provider)
	}

	started := time.Now().UTC()
	result := engine.Run(sc)
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
