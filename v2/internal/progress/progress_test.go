package progress

import (
	"sync"
	"testing"
)

// collector is a concurrency-safe capturing reporter.
type collector struct {
	mu sync.Mutex
	ev []Event
}

func (c *collector) Report(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, e)
}
func (c *collector) events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.ev...)
}

func TestNilReporterIsNoOp(t *testing.T) {
	// None of these may panic with a nil reporter.
	Report(nil, Event{Phase: PhaseCollect})
	ReportPhase(nil, PhaseGraph, "")
	NewCounter(nil, PhaseCollect, 3).Done("x")
	var c *Counter
	c.Done("x") // nil *Counter
}

func TestCounterAnnouncesAndIncrements(t *testing.T) {
	c := &collector{}
	ctr := NewCounter(c, PhaseCollect, 3)
	ctr.Done("ec2")
	ctr.Done("iam")
	ctr.Done("s3")

	ev := c.events()
	if len(ev) != 4 {
		t.Fatalf("expected 1 announce + 3 done = 4 events, got %d", len(ev))
	}
	if ev[0].Done != 0 || ev[0].Total != 3 {
		t.Fatalf("first event should announce 0/3, got %d/%d", ev[0].Done, ev[0].Total)
	}
	// done events strictly increment to total
	for i := 1; i <= 3; i++ {
		if ev[i].Done != i || ev[i].Total != 3 {
			t.Fatalf("event %d should be %d/3, got %d/%d", i, i, ev[i].Done, ev[i].Total)
		}
	}
	if ev[3].Detail != "s3" {
		t.Fatalf("detail should name the completed unit, got %q", ev[3].Detail)
	}
}

func TestCounterConcurrentDoneCountsExactly(t *testing.T) {
	c := &collector{}
	const n = 50
	ctr := NewCounter(c, PhaseCheck, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ctr.Done("x") }()
	}
	wg.Wait()

	ev := c.events()
	if len(ev) != n+1 {
		t.Fatalf("expected %d events, got %d", n+1, len(ev))
	}
	// The highest Done seen must equal n exactly (no lost/double increments).
	max := 0
	for _, e := range ev {
		if e.Done > max {
			max = e.Done
		}
	}
	if max != n {
		t.Fatalf("concurrent Done must reach exactly %d, got %d", n, max)
	}
}

func TestIndeterminate(t *testing.T) {
	if !(Event{Phase: PhaseReachability, Total: 0}).Indeterminate() {
		t.Fatal("Total 0 must be indeterminate")
	}
	if (Event{Phase: PhaseCollect, Total: 5}).Indeterminate() {
		t.Fatal("Total > 0 must be determinate")
	}
}
