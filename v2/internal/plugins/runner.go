package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/progress"
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
	return RunWithLog(ctx, m, target, nil)
}

// RunWithLog is Run with a live log: if onStderr is non-nil, each line the tool
// writes to stderr is forwarded to it as it is produced (a tool's stderr is its
// real "what's happening now" stream — DB downloads, scan progress — and is the
// honest per-tool signal, since a single tool exposes no determinate progress).
// stderr is still fully buffered for the failure path. A nil onStderr behaves
// exactly like Run.
func RunWithLog(ctx context.Context, m Manifest, target string, onStderr func(line string)) ([]findings.Finding, error) {
	// A target beginning with '-' would be parsed by the tool as a flag rather
	// than a path/image (argument injection). The target is a discrete argv
	// element (no shell), so this is the only injection vector — reject it.
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("%s: refusing target %q: must not start with '-' (would be read as a flag)", m.Name, target)
	}
	if !Available(m) {
		return nil, ErrNotAvailable
	}
	cmd := exec.CommandContext(ctx, m.Binary, m.Args(target)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	if onStderr != nil {
		lw := &lineWriter{onLine: onStderr}
		cmd.Stderr = io.MultiWriter(&stderr, lw) // buffer for errors + live forward
		runErr := cmd.Run()
		lw.flush() // emit any trailing partial line
		return finalizeRun(m, ctx.Err(), runErr, stdout.Bytes(), stderr.String())
	}
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	return finalizeRun(m, ctx.Err(), runErr, stdout.Bytes(), stderr.String())
}

// finalizeRun parses stdout into findings and classifies the run outcome. A
// non-zero exit WITH findings is the normal "found issues" case; a parse
// failure or a non-zero exit with no parseable output is a real failure.
func finalizeRun(m Manifest, ctxErr, runErr error, stdout []byte, stderr string) ([]findings.Finding, error) {
	fs, parseErr := Parse(m, stdout)
	if parseErr != nil {
		return nil, fmt.Errorf("%s: parsing output: %w (run: %v; stderr: %s)",
			m.Name, parseErr, runErr, truncate(stderr, 200))
	}
	if outcomeErr := classifyRun(m.Name, ctxErr, runErr, fs, stderr); outcomeErr != nil {
		return nil, outcomeErr
	}
	return fs, nil
}

// lineWriter forwards complete newline-terminated lines to onLine as bytes are
// written, holding any trailing partial line until the next write or flush.
type lineWriter struct {
	onLine  func(string)
	pending []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.pending[:i]), "\r")
		w.onLine(line)
		w.pending = w.pending[i+1:]
	}
	return len(p), nil
}

// flush emits any buffered partial final line (no trailing newline).
func (w *lineWriter) flush() {
	if len(w.pending) > 0 {
		w.onLine(strings.TrimRight(string(w.pending), "\r"))
		w.pending = nil
	}
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

// DefaultSweepConcurrency is the default number of tools RunAvailable runs at
// once. Tools are subprocess- and I/O-heavy (DB downloads, filesystem walks),
// so a small bound speeds a multi-tool sweep without thrashing the host.
const DefaultSweepConcurrency = 4

// RunAvailable runs every built-in tool that is installed on PATH against
// target, up to concurrency at a time, and returns one result per built-in tool
// in Builtin order regardless of completion order. A tool that is not installed
// is returned with Available=false and is not run — it is never silently
// omitted, so the caller can report the skips. RunAvailable persists nothing;
// the caller decides what to store. concurrency <= 0 means sequential (1); pass
// DefaultSweepConcurrency for the standard bound. A cancelled ctx stops the
// sweep (already-launched tools observe the cancellation through their own ctx).
func RunAvailable(ctx context.Context, target string, concurrency int) []RunResult {
	return runAvailable(ctx, target, Builtin, concurrency, nil)
}

// RunAvailableWithProgress is RunAvailable with real, per-tool progress: it
// reports the PhaseTools phase with a true done/total over the *installed*
// tools (the ones that will actually run), advancing as each completes. A
// single tool exposes no determinate progress, but the sweep does — this is the
// honest bar for "run all". r may be nil.
func RunAvailableWithProgress(ctx context.Context, target string, concurrency int, r progress.Reporter) []RunResult {
	return runAvailable(ctx, target, Builtin, concurrency, r)
}

// runAvailable is the testable core of RunAvailable, parameterized by the tool
// set so a test can supply manifests with known-absent binaries.
func runAvailable(ctx context.Context, target string, manifests []Manifest, concurrency int, r progress.Reporter) []RunResult {
	if concurrency < 1 {
		concurrency = 1
	}

	// The honest denominator for the sweep is the number of installed tools (the
	// ones that will actually run); skipped/uninstalled tools are instant and do
	// not advance the bar.
	results := make([]RunResult, len(manifests))
	installed := 0
	for i := range manifests {
		results[i].Manifest = manifests[i]
		results[i].Available = Available(manifests[i])
		if results[i].Available {
			installed++
		}
	}
	prog := progress.NewCounter(r, progress.PhaseTools, installed)

	// Pre-sized by index so results stay in Builtin order despite concurrent
	// completion; each goroutine writes only its own element's run fields. Every
	// manifest gets a result: a tool not run because the context was cancelled is
	// recorded with the cancellation error, never silently dropped, so a
	// cut-short sweep is not mistaken for a complete one.
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range manifests {
		if ctx.Err() != nil {
			results[i].Err = ctx.Err() // cancelled before this tool could run
			continue
		}
		if !results[i].Available {
			continue // not installed; skipped, not run (no error)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, mf Manifest) {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now().UTC()
			fs, err := Run(ctx, mf, target)
			results[idx].Findings = fs
			results[idx].Err = err
			results[idx].StartedAt = start
			results[idx].FinishedAt = time.Now().UTC()
			prog.Done(mf.Name)
		}(i, manifests[i])
	}

	wg.Wait()
	return results
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
