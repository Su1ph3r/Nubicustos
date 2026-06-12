package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/progress"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

type fakeCheck struct{}

func (fakeCheck) Spec() findings.CheckSpec {
	return findings.CheckSpec{ID: "test_check", Title: "fake", Provider: "test", Service: "x", Severity: findings.SeverityMedium}
}

func (fakeCheck) Evaluate(_ *ScanContext, _ *state.State) ([]findings.Finding, error) {
	return []findings.Finding{{
		ID: "f1", CheckID: "test_check", Title: "fake", Severity: findings.SeverityMedium, Status: findings.StatusOpen,
	}}, nil
}

// TestRunEmitsFindings proves the registry → check → result pipeline works
// without any cloud calls.
func TestRunEmitsFindings(t *testing.T) {
	RegisterCheck(fakeCheck{})
	r := Run(&ScanContext{Ctx: context.Background(), Provider: "test"})

	for _, f := range r.Findings {
		if f.ID == "f1" {
			return
		}
	}
	t.Fatalf("expected fake finding f1 in results, got %+v", r.Findings)
}

// TestConcurrencyBound keeps the worker-pool sizing sane on any host.
func TestConcurrencyBound(t *testing.T) {
	if n := concurrency(); n < 1 || n > 16 {
		t.Fatalf("concurrency out of bounds: %d", n)
	}
}

// noopCollector lets a test exercise the collect-phase progress without cloud calls.
type noopCollector struct{ name string }

func (c noopCollector) Name() string                               { return c.name }
func (noopCollector) Collect(_ *ScanContext, _ *state.State) error { return nil }

type progCapture struct {
	mu sync.Mutex
	ev []progress.Event
}

func (p *progCapture) Report(e progress.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ev = append(p.ev, e)
}
func (p *progCapture) snapshot() []progress.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]progress.Event(nil), p.ev...)
}

// TestRunScanReportsRealProgress proves progress reflects actual completed work:
// collect and check report true done/total reaching their unit counts, and the
// reachability + graph phases are announced as indeterminate.
func TestRunScanReportsRealProgress(t *testing.T) {
	cap := &progCapture{}
	sc := &ScanContext{Ctx: context.Background(), Provider: "test", Progress: cap}
	cs := []Collector{noopCollector{"c1"}, noopCollector{"c2"}, noopCollector{"c3"}}
	cks := []Check{fakeCheck{}, fakeCheck{}}

	runScan(sc, cs, cks)

	ev := cap.snapshot()
	maxDone := func(p progress.Phase) (max, total int, announced bool) {
		for _, e := range ev {
			if e.Phase != p {
				continue
			}
			announced = true
			total = e.Total
			if e.Done > max {
				max = e.Done
			}
		}
		return
	}

	if d, total, ok := maxDone(progress.PhaseCollect); !ok || total != len(cs) || d != len(cs) {
		t.Fatalf("collect progress should reach %d/%d, got %d/%d (announced=%v)", len(cs), len(cs), d, total, ok)
	}
	if d, total, ok := maxDone(progress.PhaseCheck); !ok || total != len(cks) || d != len(cks) {
		t.Fatalf("check progress should reach %d/%d, got %d/%d (announced=%v)", len(cks), len(cks), d, total, ok)
	}
	for _, p := range []progress.Phase{progress.PhaseReachability, progress.PhaseGraph} {
		if _, _, ok := maxDone(p); !ok {
			t.Fatalf("phase %q should be announced", p)
		}
	}
}

// TestRunScanNilProgressIsSafe confirms a scan with no reporter does not panic.
func TestRunScanNilProgressIsSafe(t *testing.T) {
	sc := &ScanContext{Ctx: context.Background(), Provider: "test"} // Progress nil
	runScan(sc, []Collector{noopCollector{"c1"}}, []Check{fakeCheck{}})
}
