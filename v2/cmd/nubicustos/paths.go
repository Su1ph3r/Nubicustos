package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

type pathsFlags struct {
	dbPath string
	scan   string
	format string
}

func newPathsCmd() *cobra.Command {
	f := &pathsFlags{}
	cmd := &cobra.Command{
		Use:   "paths",
		Short: "List attack paths from a previous scan",
		Long: "List the attack paths the graph engine derived for a scan: internet\n" +
			"exposure chains and administrative-privilege concentrations, each scored\n" +
			"0-100 with a step-by-step, resource-specific proof of concept.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPaths(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to query (or \"latest\")")
	pf.StringVar(&f.format, "format", "table", "output format: table | json")
	return cmd
}

func runPaths(ctx context.Context, f *pathsFlags) error {
	format := strings.ToLower(f.format)
	if format != "table" && format != "json" {
		return fmt.Errorf("invalid --format %q (want: table | json)", f.format)
	}

	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID, err := resolveScanID(ctx, st, f.scan)
	if err != nil {
		return err
	}

	paths, err := st.LoadAttackPaths(ctx, scanID)
	if err != nil {
		return err
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if paths == nil {
			paths = []graph.Path{}
		}
		return enc.Encode(paths)
	}
	return printPaths(scanID, paths)
}

func printPaths(scanID string, paths []graph.Path) error {
	if len(paths) == 0 {
		fmt.Printf("scan %s — no attack paths\n", scanID)
		return nil
	}
	fmt.Printf("scan %s — %d attack path(s)\n", scanID, len(paths))
	for _, p := range paths {
		fmt.Printf("\n[%3d/100 %s] %s\n", p.Score, strings.ToUpper(string(p.Severity)), p.Title)
		if p.Rationale != "" {
			fmt.Printf("  %s\n", p.Rationale)
		}
		for i, e := range p.Edges {
			src := nodeLabel(p.Nodes, e.Src)
			dst := nodeLabel(p.Nodes, e.Dst)
			arrow := fmt.Sprintf("%s → %s", src, dst)
			if e.Src == e.Dst {
				arrow = src // self-edge (a held capability, not a hop)
			}
			fmt.Printf("  %d. %s [%s]\n", i+1, arrow, e.Kind)
			if e.Detail != "" {
				fmt.Printf("       %s\n", e.Detail)
			}
			if e.PoC != "" {
				fmt.Printf("       poc: %s\n", e.PoC)
			}
		}
	}
	return nil
}

// nodeLabel resolves a node id to its display label within a path.
func nodeLabel(nodes []graph.Node, id string) string {
	for _, n := range nodes {
		if n.ID == id {
			if n.Label != "" {
				return n.Label
			}
			return n.ID
		}
	}
	return id
}
