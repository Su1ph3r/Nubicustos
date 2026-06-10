package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

type findingsFlags struct {
	dbPath   string
	scan     string
	severity string
	service  string
	format   string
}

func newFindingsCmd() *cobra.Command {
	f := &findingsFlags{}
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Query findings from a previous scan",
		Long: "List findings stored in the local database, filtered by severity and\n" +
			"service. Defaults to the most recent scan; use --scan to pick another.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFindings(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to query (or \"latest\")")
	pf.StringVar(&f.severity, "severity", "", "comma-separated severities to include (e.g. critical,high)")
	pf.StringVar(&f.service, "service", "", "comma-separated services to include (e.g. iam,s3)")
	pf.StringVar(&f.format, "format", "table", "output format: table | json")
	return cmd
}

func runFindings(ctx context.Context, f *findingsFlags) error {
	severities, err := parseSeverities(f.severity)
	if err != nil {
		return err
	}
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

	services := splitCSV(f.service)
	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{
		Severities: severities,
		Services:   services,
	})
	if err != nil {
		return err
	}
	warnUnknownServices(ctx, st, scanID, services)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if fs == nil {
			fs = []findings.Finding{}
		}
		return enc.Encode(fs)
	}
	return printFindingsTable(scanID, fs)
}

func printFindingsTable(scanID string, fs []findings.Finding) error {
	if len(fs) == 0 {
		fmt.Printf("scan %s — no findings match the filter\n", scanID)
		return nil
	}
	fmt.Printf("scan %s — %d finding(s)\n\n", scanID, len(fs))

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tSERVICE\tCHECK\tREGION\tRESOURCE")
	for _, f := range fs {
		resource := f.Resource.ID
		if resource == "" && len(f.Affected) > 0 {
			resource = fmt.Sprintf("%d affected", len(f.Affected))
		}
		region := f.Resource.Region
		if region == "" {
			region = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(f.Severity)), f.Service, f.CheckID, region, resource)
	}
	return tw.Flush()
}
