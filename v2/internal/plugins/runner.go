package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// ErrNotAvailable means the tool's binary was not found on PATH. The plugin
// model is optional, so callers treat this as "skip", not a failure.
var ErrNotAvailable = errors.New("tool not available on PATH")

// Available reports whether the tool's binary is on PATH.
func Available(m Manifest) bool {
	_, err := exec.LookPath(m.Binary)
	return err == nil
}

// Run executes the tool against target and parses its output into findings. It
// returns ErrNotAvailable (and no error to the operator's run) when the binary
// is absent. A non-zero exit is NOT treated as failure: trivy/grype/checkov/
// terrascan all exit non-zero precisely when they find issues, so the output is
// parsed regardless and an error is returned only when the output is unusable.
func Run(ctx context.Context, m Manifest, target string) ([]findings.Finding, error) {
	if !Available(m) {
		return nil, ErrNotAvailable
	}
	cmd := exec.CommandContext(ctx, m.Binary, m.Args(target)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	fs, parseErr := Parse(m, stdout.Bytes())
	if parseErr != nil {
		// The tool ran but its output could not be parsed — surface both the
		// parse failure and any run error (which carries the exit code/stderr).
		return nil, fmt.Errorf("%s: parsing output: %w (run: %v; stderr: %s)",
			m.Name, parseErr, runErr, truncate(stderr.String(), 200))
	}
	return fs, nil
}

// Parse dispatches raw tool output to the format-specific parser.
func Parse(m Manifest, raw []byte) ([]findings.Finding, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil // no output (e.g. a clean scan that printed nothing)
	}
	switch m.Format {
	case FormatTrivy:
		return parseTrivy(m, raw)
	case FormatGrype:
		return parseGrype(m, raw)
	case FormatCheckov:
		return parseCheckov(m, raw)
	case FormatTerrascan:
		return parseTerrascan(m, raw)
	case FormatKubeBench:
		return parseKubeBench(m, raw)
	default:
		return nil, fmt.Errorf("no parser for format %q", m.Format)
	}
}

// normalizeSeverity maps a tool's severity string onto the shared scale. Tools
// vary in case and vocabulary; unknown values fall back to medium so a finding
// is never silently dropped for an unrecognized label.
func normalizeSeverity(s string) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return findings.SeverityCritical
	case "high":
		return findings.SeverityHigh
	case "medium", "moderate", "warning":
		return findings.SeverityMedium
	case "low", "minor":
		return findings.SeverityLow
	case "info", "informational", "none", "unknown", "negligible":
		return findings.SeverityInfo
	default:
		return findings.SeverityMedium
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
