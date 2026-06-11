package main

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/tui"
)

type tuiFlags struct {
	dbPath string
	scan   string
}

func newTUICmd() *cobra.Command {
	f := &tuiFlags{}
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Browse a scan in the terminal UI",
		Long: "Launch the terminal UI to browse a completed scan: a dashboard, the\n" +
			"findings table with a detail pane, and the attack-path list with chained\n" +
			"PoCs. Reads a stored scan; it does not perform any cloud calls.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to browse (or \"latest\")")
	return cmd
}

func runTUI(ctx context.Context, f *tuiFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID, err := resolveScanID(ctx, st, f.scan)
	if err != nil {
		return err
	}
	meta, err := st.GetScan(ctx, scanID)
	if err != nil {
		return err
	}
	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
	if err != nil {
		return err
	}
	paths, err := st.LoadAttackPaths(ctx, scanID)
	if err != nil {
		return err
	}

	model := tui.New(tui.Data{
		ScanID:   scanID,
		Provider: meta.Provider,
		Account:  meta.Account,
		Findings: fs,
		Paths:    paths,
	})

	if _, err := tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx)).Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}
