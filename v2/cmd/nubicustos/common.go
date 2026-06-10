package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

// resolveScanID returns the requested scan id, treating "" or "latest" as the
// most recent scan. It returns an actionable error when the database is empty.
func resolveScanID(ctx context.Context, st *store.Store, requested string) (string, error) {
	if requested != "" && requested != "latest" {
		if _, err := st.GetScan(ctx, requested); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", fmt.Errorf("scan %q not found in this database", requested)
			}
			// A locked/corrupt DB or I/O error is not "not found" — surface it.
			return "", err
		}
		return requested, nil
	}
	id, err := st.LatestScanID(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no scans in this database yet — run `nubicustos scan` first")
		}
		return "", err
	}
	return id, nil
}

// parseSeverities validates and normalizes a comma-separated severity list.
func parseSeverities(csv string) ([]findings.Severity, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	valid := map[string]findings.Severity{
		"critical": findings.SeverityCritical,
		"high":     findings.SeverityHigh,
		"medium":   findings.SeverityMedium,
		"low":      findings.SeverityLow,
		"info":     findings.SeverityInfo,
	}
	var out []findings.Severity
	for _, raw := range strings.Split(csv, ",") {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		sev, ok := valid[s]
		if !ok {
			return nil, fmt.Errorf("invalid severity %q (want: critical, high, medium, low, info)", raw)
		}
		out = append(out, sev)
	}
	return out, nil
}

// warnUnknownServices prints a stderr warning for each requested --service
// value that produced no findings in the scan, so a typo (e.g. "ima" for "iam")
// is distinguishable from a genuinely empty result. It is best-effort: the
// findings have already loaded, so a diagnostic-query failure here must not fail
// the command — but it is reported rather than silently dropped.
func warnUnknownServices(ctx context.Context, st *store.Store, scanID string, requested []string) {
	if len(requested) == 0 {
		return
	}
	present, err := st.DistinctServices(ctx, scanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not verify service filter against scan %s: %v\n", scanID, err)
		return
	}
	set := make(map[string]struct{}, len(present))
	for _, s := range present {
		set[s] = struct{}{}
	}
	for _, want := range requested {
		if _, ok := set[want]; !ok {
			fmt.Fprintf(os.Stderr,
				"warning: service %q has no findings in scan %s (services present: %s)\n",
				want, scanID, strings.Join(present, ", "))
		}
	}
}

// splitCSV splits a comma-separated flag value into trimmed, non-empty tokens.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, raw := range strings.Split(s, ",") {
		if t := strings.TrimSpace(raw); t != "" {
			out = append(out, t)
		}
	}
	return out
}
