package plugins

import (
	"context"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/progress"
)

func TestLineWriterForwardsCompleteLines(t *testing.T) {
	var got []string
	lw := &lineWriter{onLine: func(s string) { got = append(got, s) }}

	// A line split across writes, a CRLF line, and a trailing partial line.
	lw.Write([]byte("Downloading DB\nScan"))
	lw.Write([]byte("ning fs\r\n"))
	lw.Write([]byte("partial-no-newline"))

	if len(got) != 2 || got[0] != "Downloading DB" || got[1] != "Scanning fs" {
		t.Fatalf("expected two complete lines (CR stripped), got %#v", got)
	}
	lw.flush() // trailing partial line emitted on flush
	if len(got) != 3 || got[2] != "partial-no-newline" {
		t.Fatalf("flush should emit the trailing partial line, got %#v", got)
	}
}

func TestLineWriterFlushNoopWhenEmpty(t *testing.T) {
	calls := 0
	lw := &lineWriter{onLine: func(string) { calls++ }}
	lw.Write([]byte("done\n"))
	lw.flush() // nothing pending
	if calls != 1 {
		t.Fatalf("flush with no pending bytes must not emit, got %d calls", calls)
	}
}

func TestRunAvailableAnnouncesToolsPhase(t *testing.T) {
	// With no tools installed in the test environment, the sweep still announces
	// the tools phase with a real (zero) installed total — never a fake bar.
	var ev []progress.Event
	rep := progress.Func(func(e progress.Event) { ev = append(ev, e) })
	runAvailable(context.Background(), ".", absentManifests(), DefaultSweepConcurrency, rep)

	if len(ev) == 0 || ev[0].Phase != progress.PhaseTools {
		t.Fatalf("the sweep must announce the tools phase, got %#v", ev)
	}
	if ev[0].Total != 0 {
		t.Fatalf("with no installed tools the denominator is 0 (honest), got %d", ev[0].Total)
	}
}
