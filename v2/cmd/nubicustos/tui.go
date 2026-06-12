package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/plugins"
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
			"findings table with a detail pane, the attack-path list with chained PoCs,\n" +
			"and a Tools view to run optional external scanners. Browsing performs no\n" +
			"cloud calls; running a tool from the Tools view executes that tool locally.",
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
	data, err := loadTUIData(ctx, st, scanID)
	if err != nil {
		return err
	}

	actions := &tuiActions{ctx: ctx, st: st, concurrency: plugins.DefaultSweepConcurrency}
	model := tui.New(data, actions)

	if _, err := tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx)).Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

// loadTUIData assembles the view data for one stored scan.
func loadTUIData(ctx context.Context, st *store.Store, scanID string) (tui.Data, error) {
	meta, err := st.GetScan(ctx, scanID)
	if err != nil {
		return tui.Data{}, err
	}
	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
	if err != nil {
		return tui.Data{}, err
	}
	paths, err := st.LoadAttackPaths(ctx, scanID)
	if err != nil {
		return tui.Data{}, err
	}
	return tui.Data{
		ScanID:   scanID,
		Provider: meta.Provider,
		Account:  meta.Account,
		Findings: fs,
		Paths:    paths,
	}, nil
}

// tuiActions implements tui.Actions over the open store + plugin runner. It
// binds the command's context so the TUI's run commands carry cancellation.
type tuiActions struct {
	ctx         context.Context
	st          *store.Store
	concurrency int
}

func (a *tuiActions) ListTools() []tui.ToolStatus {
	history := pluginScanHistory(a.ctx, a.st)
	out := make([]tui.ToolStatus, 0, len(plugins.Builtin))
	for _, m := range plugins.Builtin {
		ts := tui.ToolStatus{Name: m.Name, Category: m.Service, Available: plugins.Available(m)}
		if meta, ok := history[m.Name]; ok {
			ts.HasRun = true
			ts.LastRun = meta.StartedAt.Local().Format("2006-01-02 15:04")
			ts.Findings = meta.FindingCount
		}
		out = append(out, ts)
	}
	return out
}

func (a *tuiActions) RunTool(name, target string) (string, error) {
	if name == "" {
		results := plugins.RunAvailable(a.ctx, target, a.concurrency)
		var ran, skipped, failed, total int
		for _, r := range results {
			switch {
			case !r.Available:
				skipped++
			case r.Err != nil:
				failed++
			default:
				ran++
				total += len(r.Findings)
				if _, err := persistPluginScan(a.ctx, a.st, r.Manifest, target, r.Findings, r.StartedAt, r.FinishedAt); err != nil {
					return "", err
				}
			}
		}
		return fmt.Sprintf("ran %d, skipped %d, failed %d — %d finding(s)", ran, skipped, failed, total), nil
	}

	m, ok := plugins.Lookup(name)
	if !ok {
		return "", fmt.Errorf("unknown tool %q", name)
	}
	started := time.Now().UTC()
	fs, err := plugins.Run(a.ctx, m, target)
	if errors.Is(err, plugins.ErrNotAvailable) {
		return "", fmt.Errorf("%s is not installed", name)
	}
	if err != nil {
		return "", err
	}
	scanID, err := persistPluginScan(a.ctx, a.st, m, target, fs, started, time.Now().UTC())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ran %s — %d finding(s) (scan %s)", name, len(fs), scanID), nil
}

func (a *tuiActions) LatestData() (tui.Data, error) {
	scanID, err := a.st.LatestScanID(a.ctx)
	if err != nil {
		return tui.Data{}, err
	}
	return loadTUIData(a.ctx, a.st, scanID)
}
