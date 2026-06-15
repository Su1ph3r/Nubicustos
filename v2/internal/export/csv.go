package export

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// csvHeader is the column order for the CSV export. Kept flat and spreadsheet-
// friendly: one row per finding, with the affected-count summarizing aggregates.
var csvHeader = []string{
	"severity", "service", "check_id", "title", "account", "region",
	"resource_type", "resource_id", "reachable", "affected_count",
	"description", "remediation", "poc",
}

// CSV writes findings as a header-prefixed CSV document.
func CSV(w io.Writer, fs []findings.Finding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, f := range fs {
		rec := []string{
			csvSafe(string(f.Severity)),
			csvSafe(f.Service),
			csvSafe(f.CheckID),
			csvSafe(f.Title),
			csvSafe(f.Resource.Account),
			csvSafe(f.Resource.Region),
			csvSafe(f.Resource.Type),
			csvSafe(f.Resource.ID),
			csvSafe(string(f.Reachable)),
			strconv.Itoa(len(f.Affected)),
			csvSafe(f.Description),
			csvSafe(f.Remediation),
			csvSafe(f.PoC),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralizes spreadsheet formula injection. A cell beginning with a
// formula trigger is executed when the file is opened in Excel/Sheets/LibreOffice;
// resource ids, names, ARNs, and tags originate from the scanned account and are
// attacker-influenceable, so a resource named "=cmd|..." would otherwise become a
// live formula in the report. Prefixing a single quote forces text interpretation.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
