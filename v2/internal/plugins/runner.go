package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

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
	if outcomeErr := classifyRun(m.Name, ctx.Err(), runErr, fs, stderr.String()); outcomeErr != nil {
		return nil, outcomeErr
	}
	return fs, nil
}

// classifyRun decides whether a completed run is a clean result or a failure.
// A non-zero exit WITH findings is the normal "found issues" case; a context
// error, or a non-zero exit with NO parseable findings (DB download failed, bad
// flags, crash), is a real failure that must not be reported as a clean scan.
func classifyRun(name string, ctxErr, runErr error, fs []findings.Finding, stderr string) error {
	if ctxErr != nil {
		return fmt.Errorf("%s: %w (stderr: %s)", name, ctxErr, truncate(stderr, 200))
	}
	if runErr != nil && len(fs) == 0 {
		return fmt.Errorf("%s: exited with error and produced no findings: %v (stderr: %s)",
			name, runErr, truncate(stderr, 200))
	}
	return nil
}

// RunResult is the outcome of one tool during a sweep (RunAvailable).
type RunResult struct {
	Manifest   Manifest
	Findings   []findings.Finding
	Err        error     // non-nil if the tool was available but its run/parse failed
	Available  bool      // false → not installed; the tool was skipped, not run
	StartedAt  time.Time // when this tool's run began (zero if skipped)
	FinishedAt time.Time // when this tool's run ended (zero if skipped)
}

// RunAvailable runs every built-in tool that is installed on PATH against
// target, sequentially, and returns one result per built-in tool. A tool that
// is not installed is returned with Available=false and is not run — it is
// never silently omitted, so the caller can report the skips. RunAvailable
// persists nothing; the caller decides what to store. A cancelled ctx stops the
// sweep before the next tool.
func RunAvailable(ctx context.Context, target string) []RunResult {
	return runAvailable(ctx, target, Builtin)
}

// runAvailable is the testable core of RunAvailable, parameterized by the tool
// set so a test can supply manifests with known-absent binaries.
func runAvailable(ctx context.Context, target string, manifests []Manifest) []RunResult {
	out := make([]RunResult, 0, len(manifests))
	for _, m := range manifests {
		if ctx.Err() != nil {
			break
		}
		if !Available(m) {
			out = append(out, RunResult{Manifest: m, Available: false})
			continue
		}
		start := time.Now().UTC()
		fs, err := Run(ctx, m, target)
		out = append(out, RunResult{
			Manifest:   m,
			Findings:   fs,
			Err:        err,
			Available:  true,
			StartedAt:  start,
			FinishedAt: time.Now().UTC(),
		})
	}
	return out
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
