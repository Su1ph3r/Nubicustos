package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/store"
)

type pathsFlags struct {
	dbPath string
	scan   string
}

func newPathsCmd() *cobra.Command {
	f := &pathsFlags{}
	cmd := &cobra.Command{
		Use:   "paths",
		Short: "List attack paths from a previous scan",
		Long: "List the attack paths the graph engine derived for a scan.\n\n" +
			"The in-process attack-path graph (IAM privilege escalation, assume-role\n" +
			"chains, and internet exposure) is delivered in Phase 2; until then this\n" +
			"command reports an empty result against a completed scan.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPaths(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to query (or \"latest\")")
	return cmd
}

func runPaths(ctx context.Context, f *pathsFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID, err := resolveScanID(ctx, st, f.scan)
	if err != nil {
		return err
	}

	n, err := st.CountAttackPaths(ctx, scanID)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Printf("scan %s — no attack paths\n", scanID)
		fmt.Println("(the attack-path graph engine is delivered in Phase 2)")
		return nil
	}
	fmt.Printf("scan %s — %d attack path(s)\n", scanID, n)
	return nil
}
