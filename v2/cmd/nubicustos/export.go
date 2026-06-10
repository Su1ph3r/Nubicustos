package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/export"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

type exportFlags struct {
	dbPath   string
	scan     string
	severity string
	service  string
	out      string
}

func newExportCmd() *cobra.Command {
	f := &exportFlags{}
	cmd := &cobra.Command{
		Use:   "export [cairn|sarif|csv|html]",
		Short: "Export findings from a previous scan",
		Long: "Re-serialize stored findings into a downstream format without rescanning:\n" +
			"  cairn  normalized JSON for the Cairn/Vinculum pipeline\n" +
			"  sarif  SARIF 2.1.0 for code-scanning dashboards\n" +
			"  csv    flat spreadsheet rows\n" +
			"  html   self-contained shareable report\n\n" +
			"Defaults to the most recent scan and stdout; use --scan and --out to override.",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"cairn", "sarif", "csv", "html"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(cmd.Context(), strings.ToLower(args[0]), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to export (or \"latest\")")
	pf.StringVar(&f.severity, "severity", "", "comma-separated severities to include (e.g. critical,high)")
	pf.StringVar(&f.service, "service", "", "comma-separated services to include (e.g. iam,s3)")
	pf.StringVar(&f.out, "out", "", "output file (default: stdout)")
	return cmd
}

func runExport(ctx context.Context, format string, f *exportFlags) error {
	switch format {
	case "cairn", "sarif", "csv", "html":
	default:
		return fmt.Errorf("unknown export format %q (want: cairn | sarif | csv | html)", format)
	}

	severities, err := parseSeverities(f.severity)
	if err != nil {
		return err
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
	meta, err := st.GetScan(ctx, scanID)
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

	var file *os.File
	w := io.Writer(os.Stdout)
	if f.out != "" {
		file, err = os.Create(f.out)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		w = file
	}

	now := time.Now().UTC()
	switch format {
	case "cairn":
		err = export.Cairn(w, meta.Provider, meta.Account, fs, now)
	case "sarif":
		err = export.SARIF(w, fs, now)
	case "csv":
		err = export.CSV(w, fs)
	case "html":
		err = export.HTML(w, meta.Provider, meta.Account, fs, now)
	}

	// For a file sink, buffered-write/flush failures (ENOSPC, quota, network FS
	// commit) can surface only at Close — so the success path must observe it,
	// or a truncated file gets reported as a successful export.
	if file != nil {
		if cerr := file.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("closing output file %s: %w", f.out, cerr)
		}
	}
	if err != nil {
		return err
	}

	if f.out != "" {
		fmt.Fprintf(os.Stderr, "exported %d finding(s) from scan %s as %s to %s\n",
			len(fs), scanID, format, f.out)
	}
	return nil
}
