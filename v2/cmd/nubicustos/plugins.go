package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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

func newPluginsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List supported tools and whether each is installed",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TOOL\tCATEGORY\tBINARY\tAVAILABLE")
			for _, m := range plugins.Builtin {
				avail := "no"
				if plugins.Available(m) {
					avail = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Name, m.Service, m.Binary, avail)
			}
			return tw.Flush()
		},
	}
}

type pluginsRunFlags struct {
	target string
	dbPath string
}

func newPluginsRunCmd() *cobra.Command {
	f := &pluginsRunFlags{}
	cmd := &cobra.Command{
		Use:   "run <tool>",
		Short: "Run a tool and persist its findings as a scan",
		Long: "Run a supported tool against a target, normalize its output into findings,\n" +
			"and persist them as a scan (provider \"plugin:<tool>\") so they are queryable\n" +
			"and exportable like native findings.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlugin(cmd.Context(), args[0], f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.target, "target", ".", "scan target (path, image, or directory) — ignored by tools that scan the local node")
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
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

	scanID := newScanID()
	if err := st.CreateScan(ctx, scanID, "plugin:"+m.Name, f.target, m.Binary, started); err != nil {
		return err
	}
	if err := st.SaveFindings(ctx, scanID, fs, finished); err != nil {
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
