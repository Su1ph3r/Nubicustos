package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/diff"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

type diffFlags struct {
	dbPath string
	from   string
	to     string
	format string
	failOn string
}

func newDiffCmd() *cobra.Command {
	f := &diffFlags{}
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scans to surface posture drift",
		Long: "Diff two stored scans of the same estate and report what changed:\n" +
			"findings added or resolved, exposures that opened (a finding that became\n" +
			"internet-reachable), severity shifts, and attack paths gained or lost.\n\n" +
			"Defaults to comparing the most recent scan against the one before it.\n" +
			"Point-in-time scanners cannot do this; the delta is computed locally over\n" +
			"the persisted scan history, so it is exact and makes a clean CI change-gate\n" +
			"(see --fail-on).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiff(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.to, "to", "latest", "newer scan id to compare (or \"latest\")")
	pf.StringVar(&f.from, "from", "", "baseline scan id (default: the scan before --to)")
	pf.StringVar(&f.format, "format", "table", "output format: table | json")
	pf.StringVar(&f.failOn, "fail-on", "", "exit non-zero on regressions: any | reachable | paths")
	return cmd
}

func runDiff(ctx context.Context, f *diffFlags) error {
	format := strings.ToLower(f.format)
	if format != "table" && format != "json" {
		return fmt.Errorf("invalid --format %q (want: table | json)", f.format)
	}
	failOn := strings.ToLower(strings.TrimSpace(f.failOn))
	switch failOn {
	case "", "any", "reachable", "paths":
	default:
		return fmt.Errorf("invalid --fail-on %q (want: any | reachable | paths)", f.failOn)
	}

	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	toID, err := resolveScanID(ctx, st, f.to)
	if err != nil {
		return err
	}

	var fromID string
	if strings.TrimSpace(f.from) == "" {
		fromID, err = st.PreviousScanID(ctx, toID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("scan %s is the earliest scan — need at least two scans to diff (or pass --from)", toID)
			}
			return err
		}
	} else {
		fromID, err = resolveScanID(ctx, st, f.from)
		if err != nil {
			return err
		}
	}
	if fromID == toID {
		return fmt.Errorf("--from and --to resolve to the same scan (%s); nothing to compare", toID)
	}

	fromSnap, err := loadSnapshot(ctx, st, fromID)
	if err != nil {
		return err
	}
	toSnap, err := loadSnapshot(ctx, st, toID)
	if err != nil {
		return err
	}

	res := diff.Compute(fromSnap, toSnap)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else if err := printDiff(res); err != nil {
		return err
	}

	if regressed(res, failOn) {
		return fmt.Errorf("regressions detected (--fail-on %s)", failOn)
	}
	return nil
}

// loadSnapshot reads a scan's findings and attack paths into a diff.Snapshot.
func loadSnapshot(ctx context.Context, st *store.Store, scanID string) (diff.Snapshot, error) {
	meta, err := st.GetScan(ctx, scanID)
	if err != nil {
		return diff.Snapshot{}, err
	}
	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
	if err != nil {
		return diff.Snapshot{}, err
	}
	paths, err := st.LoadAttackPaths(ctx, scanID)
	if err != nil {
		return diff.Snapshot{}, err
	}
	return diff.Snapshot{
		ScanID:    scanID,
		StartedAt: meta.StartedAt,
		Findings:  fs,
		Paths:     paths,
	}, nil
}

// regressed reports whether the diff trips the requested --fail-on threshold.
// "any" trips on any new finding, opened exposure, severity increase, or new
// attack path; "reachable" trips only on freshly internet-reachable findings;
// "paths" trips only on newly-gained attack paths. Resolved findings and
// severity decreases are improvements and never trip a gate.
func regressed(r diff.Result, failOn string) bool {
	switch failOn {
	case "reachable":
		return len(r.NewlyReachable) > 0
	case "paths":
		return len(r.AddedPaths) > 0
	case "any":
		return len(r.Added) > 0 || len(r.NewlyReachable) > 0 ||
			len(r.SeverityUp) > 0 || len(r.AddedPaths) > 0
	default:
		return false
	}
}

func printDiff(r diff.Result) error {
	fmt.Printf("diff %s (%s) -> %s (%s)\n",
		r.FromScanID, fmtTime(r.FromTime), r.ToScanID, fmtTime(r.ToTime))

	if r.Empty() {
		fmt.Println("\nno changes — posture is identical across both scans")
		return nil
	}

	fmt.Printf("\n  + %d new   - %d resolved   ! %d newly reachable   ^ %d severity up   v %d severity down   +%d / -%d attack paths\n",
		len(r.Added), len(r.Resolved), len(r.NewlyReachable),
		len(r.SeverityUp), len(r.SeverityDown), len(r.AddedPaths), len(r.RemovedPaths))

	// Regressions first (what got worse), then improvements.
	printFindingSection("NEWLY INTERNET-REACHABLE (exposure opened since baseline)", r.NewlyReachable)
	printPathSection("NEW ATTACK PATHS (privilege/exposure chain gained since baseline)", r.AddedPaths)
	printFindingSection("NEW FINDINGS", r.Added)
	printSeveritySection("SEVERITY INCREASED", r.SeverityUp)
	printSeveritySection("SEVERITY DECREASED", r.SeverityDown)
	printPathSection("REMOVED ATTACK PATHS", r.RemovedPaths)
	printFindingSection("RESOLVED FINDINGS", r.Resolved)
	return nil
}

func printFindingSection(title string, fs []findings.Finding) {
	if len(fs) == 0 {
		return
	}
	fmt.Printf("\n%s\n", title)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SEVERITY\tSERVICE\tCHECK\tREGION\tRESOURCE\tREACHABLE")
	for _, f := range fs {
		resource := f.Resource.ID
		if resource == "" && len(f.Affected) > 0 {
			resource = fmt.Sprintf("%d affected", len(f.Affected))
		}
		region := f.Resource.Region
		if region == "" {
			region = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(f.Severity)), f.Service, f.CheckID, region, resource, f.Reachable)
	}
	tw.Flush()
}

func printSeveritySection(title string, cs []diff.SeverityChange) {
	if len(cs) == 0 {
		return
	}
	fmt.Printf("\n%s\n", title)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  CHANGE\tSERVICE\tCHECK\tRESOURCE")
	for _, c := range cs {
		change := fmt.Sprintf("%s -> %s", strings.ToUpper(string(c.From)), strings.ToUpper(string(c.To)))
		resource := c.Finding.Resource.ID
		if resource == "" {
			resource = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", change, c.Finding.Service, c.Finding.CheckID, resource)
	}
	tw.Flush()
}

func printPathSection(title string, paths []graph.Path) {
	if len(paths) == 0 {
		return
	}
	fmt.Printf("\n%s\n", title)
	for _, p := range paths {
		fmt.Printf("  [%3d/100 %s] %s\n", p.Score, strings.ToUpper(string(p.Severity)), p.Title)
		if p.Rationale != "" {
			fmt.Printf("      %s\n", p.Rationale)
		}
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}
