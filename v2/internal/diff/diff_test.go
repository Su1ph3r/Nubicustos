package diff

import (
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
)

func f(id string, sev findings.Severity, reach findings.Reachability) findings.Finding {
	return findings.Finding{
		ID:        id,
		CheckID:   "chk_" + id,
		Severity:  sev,
		Service:   "s3",
		Reachable: reach,
		Resource:  findings.Resource{ID: "res_" + id},
	}
}

func snap(id string, t time.Time, fs []findings.Finding, ps []graph.Path) Snapshot {
	return Snapshot{ScanID: id, StartedAt: t, Findings: fs, Paths: ps}
}

func TestCompute_AddedAndResolved(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)

	from := snap("s0", t0, []findings.Finding{
		f("a", findings.SeverityHigh, findings.ReachUnknown),
		f("b", findings.SeverityLow, findings.ReachUnknown),
	}, nil)
	to := snap("s1", t1, []findings.Finding{
		f("a", findings.SeverityHigh, findings.ReachUnknown),   // unchanged
		f("c", findings.SeverityMedium, findings.ReachUnknown), // new
	}, nil)

	r := Compute(from, to)

	if len(r.Added) != 1 || r.Added[0].ID != "c" {
		t.Fatalf("Added = %+v, want [c]", r.Added)
	}
	if len(r.Resolved) != 1 || r.Resolved[0].ID != "b" {
		t.Fatalf("Resolved = %+v, want [b]", r.Resolved)
	}
	if r.Empty() {
		t.Fatal("Empty() = true, want false")
	}
	if r.FromScanID != "s0" || r.ToScanID != "s1" {
		t.Fatalf("scan ids = %s,%s", r.FromScanID, r.ToScanID)
	}
}

func TestCompute_NewlyReachable(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name     string
		from, to findings.Reachability
		wantOpen bool
	}{
		{"unknown to reachable", findings.ReachUnknown, findings.ReachYes, true},
		{"not-reachable to reachable", findings.ReachNo, findings.ReachYes, true},
		{"already reachable stays", findings.ReachYes, findings.ReachYes, false},
		{"reachable to not", findings.ReachYes, findings.ReachNo, false},
		{"unknown stays unknown", findings.ReachUnknown, findings.ReachUnknown, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			from := snap("s0", now, []findings.Finding{f("a", findings.SeverityHigh, tc.from)}, nil)
			to := snap("s1", now, []findings.Finding{f("a", findings.SeverityHigh, tc.to)}, nil)
			r := Compute(from, to)
			got := len(r.NewlyReachable) == 1
			if got != tc.wantOpen {
				t.Fatalf("NewlyReachable present = %v, want %v (n=%d)", got, tc.wantOpen, len(r.NewlyReachable))
			}
			// A reachability transition is not an add or resolve.
			if len(r.Added) != 0 || len(r.Resolved) != 0 {
				t.Fatalf("unexpected add/resolve: %+v / %+v", r.Added, r.Resolved)
			}
		})
	}
}

func TestCompute_SeverityChange(t *testing.T) {
	now := time.Now().UTC()
	from := snap("s0", now, []findings.Finding{
		f("up", findings.SeverityLow, findings.ReachUnknown),
		f("down", findings.SeverityCritical, findings.ReachUnknown),
		f("same", findings.SeverityMedium, findings.ReachUnknown),
	}, nil)
	to := snap("s1", now, []findings.Finding{
		f("up", findings.SeverityHigh, findings.ReachUnknown),
		f("down", findings.SeverityMedium, findings.ReachUnknown),
		f("same", findings.SeverityMedium, findings.ReachUnknown),
	}, nil)

	r := Compute(from, to)
	if len(r.SeverityUp) != 1 || r.SeverityUp[0].Finding.ID != "up" {
		t.Fatalf("SeverityUp = %+v", r.SeverityUp)
	}
	if r.SeverityUp[0].From != findings.SeverityLow || r.SeverityUp[0].To != findings.SeverityHigh {
		t.Fatalf("SeverityUp transition = %s->%s", r.SeverityUp[0].From, r.SeverityUp[0].To)
	}
	if len(r.SeverityDown) != 1 || r.SeverityDown[0].Finding.ID != "down" {
		t.Fatalf("SeverityDown = %+v", r.SeverityDown)
	}
}

func TestCompute_Paths(t *testing.T) {
	now := time.Now().UTC()
	p := func(id string, score int) graph.Path {
		return graph.Path{ID: id, Score: score, Severity: findings.SeverityHigh, Title: "path " + id}
	}
	from := snap("s0", now, nil, []graph.Path{p("keep", 50), p("gone", 30)})
	to := snap("s1", now, nil, []graph.Path{p("keep", 50), p("new", 90)})

	r := Compute(from, to)
	if len(r.AddedPaths) != 1 || r.AddedPaths[0].ID != "new" {
		t.Fatalf("AddedPaths = %+v", r.AddedPaths)
	}
	if len(r.RemovedPaths) != 1 || r.RemovedPaths[0].ID != "gone" {
		t.Fatalf("RemovedPaths = %+v", r.RemovedPaths)
	}
}

func TestCompute_IdenticalIsEmpty(t *testing.T) {
	now := time.Now().UTC()
	fs := []findings.Finding{f("a", findings.SeverityHigh, findings.ReachYes)}
	ps := []graph.Path{{ID: "p", Score: 10}}
	r := Compute(snap("s0", now, fs, ps), snap("s1", now, fs, ps))
	if !r.Empty() {
		t.Fatalf("Empty() = false for identical scans: %+v", r)
	}
}

func TestCompute_SortedMostSevereFirst(t *testing.T) {
	now := time.Now().UTC()
	to := snap("s1", now, []findings.Finding{
		f("low", findings.SeverityLow, findings.ReachUnknown),
		f("crit", findings.SeverityCritical, findings.ReachUnknown),
		f("med", findings.SeverityMedium, findings.ReachUnknown),
	}, nil)
	r := Compute(snap("s0", now, nil, nil), to)
	if len(r.Added) != 3 {
		t.Fatalf("Added len = %d", len(r.Added))
	}
	if r.Added[0].ID != "crit" || r.Added[1].ID != "med" || r.Added[2].ID != "low" {
		t.Fatalf("Added not severity-sorted: %s,%s,%s", r.Added[0].ID, r.Added[1].ID, r.Added[2].ID)
	}
}
