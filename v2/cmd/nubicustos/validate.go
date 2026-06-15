package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/validate"
)

type validateFlags struct {
	dbPath string
	scan   string

	// AWS auth — used only when the stored scan has authenticated-vantage
	// findings (e.g. public snapshots/AMIs) that need a live session to confirm.
	profile        string
	region         string
	mfaSerial      string
	mfaToken       string
	ssoLogin       bool
	sessionDur     time.Duration
	nonInteractive bool
}

func newValidateCmd() *cobra.Command {
	f := &validateFlags{}
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Actively (read-only) confirm a previous scan's findings",
		Long: "Run the opt-in active-validation pass over a stored scan: confirm\n" +
			"findings with captured evidence (read-only, rate-limited) and persist the\n" +
			"evidence back to the scan. Reaches out to the scanned resources, so it runs\n" +
			"only when you invoke it — never as part of a plain scan.\n\n" +
			"External-vantage validators (public-bucket listing, RDS reachability) need no\n" +
			"credentials. If the stored scan also has authenticated-vantage findings\n" +
			"(public snapshots/AMIs), the AWS auth flags below are used to resolve a\n" +
			"read-only session so those can be confirmed too; without it they are skipped.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to validate (or \"latest\")")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile (authenticated-vantage findings)")
	pf.StringVar(&f.region, "region", "", "AWS region for the auth session (authenticated-vantage findings)")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN (static-keys + MFA-condition profiles)")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` automatically if the SSO session is expired")
	pf.DurationVar(&f.sessionDur, "session-duration", 0, "temp-credential lifetime (e.g. 8h); default 12h")
	pf.BoolVar(&f.nonInteractive, "non-interactive", false, "never prompt; fail fast if MFA input is required")
	return cmd
}

func runValidate(ctx context.Context, f *validateFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID, err := resolveScanID(ctx, st, f.scan)
	if err != nil {
		return err
	}

	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
	if err != nil {
		return err
	}

	// External-vantage validators need no session. Resolve credentials only when
	// the stored scan actually has authenticated-vantage findings to confirm, so
	// validating an external-only scan never triggers an auth prompt.
	var venv validate.Env
	if authN := validate.AuthenticatedFindingCount(fs); authN > 0 {
		prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteractive)
		cfg, ident, path, aerr := auth.ResolveAWS(ctx, auth.AWSOptions{
			Profile:         f.profile,
			Region:          f.region,
			MFASerial:       f.mfaSerial,
			MFAToken:        f.mfaToken,
			SessionDuration: f.sessionDur,
			AllowSSOLogin:   f.ssoLogin,
		}, prompter)
		if aerr != nil {
			// Don't abort: the external-vantage validators can still run. Surface
			// the skip explicitly so it isn't mistaken for a clean result.
			fmt.Fprintf(os.Stderr,
				"warning: could not authenticate to AWS (%v); %d authenticated-vantage finding(s) will be skipped — re-run with --profile/--region or valid credentials\n",
				aerr, authN)
		} else {
			venv = validate.NewAWSEnv(cfg)
			fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)
		}
	}

	rep := validate.Run(ctx, fs, validate.Options{Env: venv})
	fmt.Fprintf(os.Stderr, "validation: %d confirmed of %d attempted\n", rep.Confirmed, rep.Attempted)
	for _, e := range rep.Errors {
		fmt.Fprintf(os.Stderr, "  validation error: %v\n", e)
	}

	// Persist the attached evidence back onto the same scan (idempotent replace).
	if err := st.SaveFindings(ctx, scanID, fs, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Printf("scan %s — evidence updated for %d finding(s)\n", scanID, rep.Attempted)
	return nil
}
