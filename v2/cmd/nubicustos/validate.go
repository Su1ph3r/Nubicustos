package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/validate"
)

type validateFlags struct {
	dbPath string
	scan   string
}

func newValidateCmd() *cobra.Command {
	f := &validateFlags{}
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Actively (read-only) confirm a previous scan's findings",
		Long: "Run the opt-in active-validation pass over a stored scan: confirm\n" +
			"findings with captured evidence (read-only, rate-limited) and persist the\n" +
			"evidence back to the scan. Reaches out to the scanned resources, so it runs\n" +
			"only when you invoke it — never as part of a plain scan.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to validate (or \"latest\")")
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

	rep := validate.Run(ctx, fs, validate.Options{})
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
