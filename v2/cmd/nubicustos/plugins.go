package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/plugins"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Optional external-tool integrations (trivy, grype, checkov, ...)",
		Long: "Run well-known read-only scanners if they are installed and normalize\n" +
			"their output into the findings model. Tools are optional: an absent tool is\n" +
			"skipped, never required.",
	}
	cmd.AddCommand(newPluginsListCmd())
	cmd.AddCommand(newPluginsRunCmd())
	return cmd
}

type pluginsListFlags struct {
	dbPath string
}

func newPluginsListCmd() *cobra.Command {
	f := &pluginsListFlags{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List supported tools, install status, and last run",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPluginsList(cmd.Context(), f)
		},
	}
	cmd.Flags().StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	return cmd
}

func runPluginsList(ctx context.Context, f *pluginsListFlags) error {
	last := latestPluginScans(ctx, f.dbPath)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tCATEGORY\tBINARY\tAVAILABLE\tLAST RUN\tFINDINGS")
	for _, m := range plugins.Builtin {
		avail := "no"
		if plugins.Available(m) {
			avail = "yes"
		}
		lastRun, count := "-", "-"
		if meta, ok := last[m.Name]; ok {
			lastRun = meta.StartedAt.Local().Format("2006-01-02 15:04")
			count = strconv.Itoa(meta.FindingCount)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", m.Name, m.Service, m.Binary, avail, lastRun, count)
	}
	return tw.Flush()
}

// latestPluginScans returns the most recent stored scan per plugin tool, keyed
// by tool name. Best-effort: if the database file does not exist yet or cannot
// be read, it returns an empty map so `list` still shows install status without
// creating a database as a side effect.
func latestPluginScans(ctx context.Context, dbPath string) map[string]store.ScanMeta {
	out := map[string]store.ScanMeta{}
	if _, err := os.Stat(dbPath); err != nil {
		return out // no database yet → no run history
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return out
	}
	defer st.Close()
	scans, err := st.ListScans(ctx, 0)
	if err != nil {
		return out
	}
	for _, sm := range scans { // newest-first, so the first per tool is the latest
		name, ok := strings.CutPrefix(sm.Provider, "plugin:")
		if !ok {
			continue
		}
		if _, seen := out[name]; !seen {
			out[name] = sm
		}
	}
	return out
}

type pluginsRunFlags struct {
	target string
	dbPath string
	all    bool
}

func newPluginsRunCmd() *cobra.Command {
	f := &pluginsRunFlags{}
	cmd := &cobra.Command{
		Use:   "run [tool]",
		Short: "Run a tool (or every installed tool) and persist its findings as a scan",
		Long: "Run a supported tool against a target, normalize its output into findings,\n" +
			"and persist them as a scan (provider \"plugin:<tool>\") so they are queryable\n" +
			"and exportable like native findings. With --all, run every installed tool in\n" +
			"one sweep, skipping (and reporting) any that are not on PATH.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.all {
				if len(args) > 0 {
					return fmt.Errorf("pass either a tool name or --all, not both")
				}
				return runPluginAll(cmd.Context(), f)
			}
			if len(args) != 1 {
				return fmt.Errorf("specify a tool (see `nubicustos plugins list`) or use --all")
			}
			return runPlugin(cmd.Context(), args[0], f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.target, "target", ".", "scan target (path, image, or directory) — ignored by tools that scan the local node")
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.BoolVar(&f.all, "all", false, "run every installed tool (those not on PATH are skipped and reported)")
	return cmd
}

func runPlugin(ctx context.Context, tool string, f *pluginsRunFlags) error {
	m, ok := plugins.Lookup(tool)
	if !ok {
		return fmt.Errorf("unknown tool %q (see `nubicustos plugins list`)", tool)
	}

	started := time.Now().UTC()
	fs, err := plugins.Run(ctx, m, f.target)
	if errors.Is(err, plugins.ErrNotAvailable) {
		return fmt.Errorf("%s is not installed (binary %q not on PATH)", m.Name, m.Binary)
	}
	if err != nil {
		return err
	}
	finished := time.Now().UTC()

	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID, err := persistPluginScan(ctx, st, m, f.target, fs, started, finished)
	if err != nil {
		return err
	}

	fmt.Printf("plugin %s — %d finding(s) (scan %s)\n", m.Name, len(fs), scanID)
	for _, sev := range severityOrder {
		if n := countSeverity(fs, sev); n > 0 {
			fmt.Printf("  %-8s %d\n", strings.ToUpper(string(sev)), n)
		}
	}
	return nil
}

// runPluginAll runs every installed tool in one sweep, persists each tool's
// findings as its own scan, and reports which ran, which were skipped (not
// installed), and which failed — never silently dropping any tool.
func runPluginAll(ctx context.Context, f *pluginsRunFlags) error {
	results := plugins.RunAvailable(ctx, f.target)

	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	var ran, skipped, failed, total int
	var failures []string

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tSTATUS\tFINDINGS\tSCAN")
	for _, r := range results {
		switch {
		case !r.Available:
			skipped++
			fmt.Fprintf(tw, "%s\tskipped (not installed)\t-\t-\n", r.Manifest.Name)
		case r.Err != nil:
			failed++
			failures = append(failures, fmt.Sprintf("%s: %v", r.Manifest.Name, r.Err))
			fmt.Fprintf(tw, "%s\terror\t-\t-\n", r.Manifest.Name)
		default:
			ran++
			total += len(r.Findings)
			scanID, perr := persistPluginScan(ctx, st, r.Manifest, f.target, r.Findings, r.StartedAt, r.FinishedAt)
			if perr != nil {
				return perr
			}
			fmt.Fprintf(tw, "%s\tran\t%d\t%s\n", r.Manifest.Name, len(r.Findings), scanID)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Printf("\n%d tool(s) ran, %d skipped, %d failed; %d finding(s) total\n", ran, skipped, failed, total)
	for _, msg := range failures {
		fmt.Fprintf(os.Stderr, "  tool error: %s\n", msg)
	}
	if ran == 0 && failed == 0 {
		fmt.Fprintln(os.Stderr, "no supported tools are installed on PATH (see `nubicustos plugins list`)")
	}
	return nil
}

// persistPluginScan writes a tool's findings as a plugin scan and returns its id.
func persistPluginScan(ctx context.Context, st *store.Store, m plugins.Manifest, target string, fs []findings.Finding, started, finished time.Time) (string, error) {
	scanID := newScanID()
	if err := st.CreateScan(ctx, scanID, "plugin:"+m.Name, target, m.Binary, started); err != nil {
		return "", err
	}
	if err := st.SaveFindings(ctx, scanID, fs, finished); err != nil {
		return "", err
	}
	return scanID, nil
}
