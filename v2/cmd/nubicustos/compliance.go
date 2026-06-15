package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/compliance"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/store"

	// Import the check packages so engine.Checks() is populated with the full
	// catalog (init-time registration), giving an accurate coverage matrix.
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/k8s"
)

type complianceFlags struct {
	framework string
	dbPath    string
	scan      string
	format    string
}

func newComplianceCmd() *cobra.Command {
	f := &complianceFlags{}
	cmd := &cobra.Command{
		Use:   "compliance --framework soc2|pci|nist",
		Short: "Map native checks (and a scan's findings) onto a compliance framework",
		Long: "Show which framework controls Nubicustos's native checks assess, on top\n" +
			"of the per-check CIS / Well-Architected references. Supported frameworks:\n" +
			"  soc2  SOC 2 Trust Services Criteria\n" +
			"  pci   PCI-DSS v4.0\n" +
			"  nist  NIST SP 800-53 Rev.5\n\n" +
			"With a results database (--db), a scan's open findings mark each control\n" +
			"pass/fail; without findings it is a pure coverage matrix.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCompliance(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.framework, "framework", "", "compliance framework: soc2 | pci | nist (required)")
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "results database to overlay findings from (optional)")
	pf.StringVar(&f.scan, "scan", "", "scan id to overlay (default: latest; ignored if no database)")
	pf.StringVar(&f.format, "format", "text", "output format: text | json")
	return cmd
}

func runCompliance(ctx context.Context, f *complianceFlags) error {
	framework := strings.ToLower(f.framework)
	if !compliance.ValidFramework(framework) {
		return fmt.Errorf("--framework must be soc2 | pci | nist")
	}

	// The full registered check catalog drives coverage.
	var specs []findings.CheckSpec
	for _, c := range engine.Checks() {
		specs = append(specs, c.Spec())
	}

	// Optionally overlay a scan's findings to mark controls pass/fail. A missing
	// database is not an error — the coverage matrix still stands on its own.
	var fs []findings.Finding
	if st, err := store.Open(ctx, f.dbPath); err == nil {
		defer st.Close()
		if scanID, err := resolveScanID(ctx, st, f.scan); err == nil {
			fs, _ = st.LoadFindings(ctx, scanID, store.FindingFilter{})
		}
	}

	rep := compliance.Build(framework, specs, fs)

	if f.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printCompliance(rep, len(fs) > 0)
	return nil
}

func printCompliance(rep compliance.Report, withFindings bool) {
	fmt.Printf("COMPLIANCE — %s · %d control(s) covered", strings.ToUpper(rep.Framework), rep.Covered)
	if withFindings {
		fmt.Printf(" · %d failing", rep.Failing)
	}
	fmt.Print("\n\n")

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, c := range rep.Controls {
		status := "covered"
		if withFindings {
			status = strings.ToUpper(c.Status)
			if c.Status == "fail" {
				status = fmt.Sprintf("FAIL (%d)", c.OpenFindings)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t(%d check(s))\n", c.Control.ID, status, c.Control.Title, len(c.CheckIDs))
	}
	tw.Flush()
}
