// Package diff computes the delta between two persisted scans of the same
// estate: which findings are new, which were resolved, which exposures opened
// (a finding that became internet-reachable), which severities moved, and which
// attack paths a principal gained or lost.
//
// This is a differentiator stateless scanners cannot replicate by construction.
// Scout/Prowler/CloudSploit evaluate a single point in time; they have no memory
// of a prior scan, so they can never say "this resource became reachable since
// last week" or "this principal gained a privilege-escalation path." Nubicustos
// persists every scan to the embedded SQLite store, so the delta is a pure local
// computation over two snapshots — no cloud calls, exact, and reproducible.
//
// The computation is deliberately storage-agnostic: it operates on already-
// loaded Snapshot values so it is trivial to unit-test and so the store stays
// the only package that knows about SQL.
package diff

import (
	"sort"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
)

// Snapshot is one scan's persisted result — the unit a diff is computed over.
// Findings and Paths are matched across snapshots by their stable IDs
// (Finding.ID is "checkID::resourceID"; Path.ID is graph-assigned), so the same
// misconfiguration on the same resource is recognized as the same item between
// scans even as its severity or reachability changes.
type Snapshot struct {
	ScanID    string
	StartedAt time.Time
	Findings  []findings.Finding
	Paths     []graph.Path
}

// SeverityChange records a finding present in both scans whose severity moved.
type SeverityChange struct {
	Finding findings.Finding  `json:"finding"` // the current (to-scan) finding
	From    findings.Severity `json:"from"`
	To      findings.Severity `json:"to"`
}

// Result is the computed delta from one scan to a later one. Every slice is
// sorted deterministically (most-severe first for findings, highest score first
// for paths) so output and tests are stable.
type Result struct {
	FromScanID string    `json:"from_scan_id"`
	ToScanID   string    `json:"to_scan_id"`
	FromTime   time.Time `json:"from_time"`
	ToTime     time.Time `json:"to_time"`

	// Added are findings present in the to-scan and absent in the from-scan.
	Added []findings.Finding `json:"added"`
	// Resolved are findings present in the from-scan and absent in the to-scan.
	Resolved []findings.Finding `json:"resolved"`
	// NewlyReachable are findings present in both scans whose reachability
	// transitioned to "reachable" — an exposure that opened since the prior scan.
	// This is the headline regression signal for change-gating in CI.
	NewlyReachable []findings.Finding `json:"newly_reachable"`
	// SeverityUp / SeverityDown are findings present in both whose severity rose
	// or fell between scans.
	SeverityUp   []SeverityChange `json:"severity_up"`
	SeverityDown []SeverityChange `json:"severity_down"`
	// AddedPaths are attack paths (privilege-escalation / internet-exposure
	// chains) a principal or resource gained since the prior scan.
	AddedPaths []graph.Path `json:"added_paths"`
	// RemovedPaths are attack paths that no longer exist in the to-scan.
	RemovedPaths []graph.Path `json:"removed_paths"`
}

// Empty reports whether the two scans are identical across every tracked
// dimension (nothing added, resolved, opened, re-scored, or re-pathed).
func (r Result) Empty() bool {
	return len(r.Added) == 0 && len(r.Resolved) == 0 && len(r.NewlyReachable) == 0 &&
		len(r.SeverityUp) == 0 && len(r.SeverityDown) == 0 &&
		len(r.AddedPaths) == 0 && len(r.RemovedPaths) == 0
}

// Compute returns the delta from the older snapshot to the newer one. It does
// not assume StartedAt ordering — the caller decides which snapshot is "from"
// (the baseline) and which is "to" (the current); Compute reports changes as if
// moving from the first argument to the second.
func Compute(from, to Snapshot) Result {
	res := Result{
		FromScanID: from.ScanID,
		ToScanID:   to.ScanID,
		FromTime:   from.StartedAt,
		ToTime:     to.StartedAt,
	}

	fromByID := indexFindings(from.Findings)
	toByID := indexFindings(to.Findings)

	for id, tf := range toByID {
		ff, ok := fromByID[id]
		if !ok {
			res.Added = append(res.Added, tf)
			continue
		}
		// Present in both: note exposure-opened and severity transitions.
		if becameReachable(ff.Reachable, tf.Reachable) {
			res.NewlyReachable = append(res.NewlyReachable, tf)
		}
		switch {
		case tf.Severity.Rank() > ff.Severity.Rank():
			res.SeverityUp = append(res.SeverityUp, SeverityChange{Finding: tf, From: ff.Severity, To: tf.Severity})
		case tf.Severity.Rank() < ff.Severity.Rank():
			res.SeverityDown = append(res.SeverityDown, SeverityChange{Finding: tf, From: ff.Severity, To: tf.Severity})
		}
	}
	for id, ff := range fromByID {
		if _, ok := toByID[id]; !ok {
			res.Resolved = append(res.Resolved, ff)
		}
	}

	fromPaths := indexPaths(from.Paths)
	toPaths := indexPaths(to.Paths)
	for id, tp := range toPaths {
		if _, ok := fromPaths[id]; !ok {
			res.AddedPaths = append(res.AddedPaths, tp)
		}
	}
	for id, fp := range fromPaths {
		if _, ok := toPaths[id]; !ok {
			res.RemovedPaths = append(res.RemovedPaths, fp)
		}
	}

	sortFindings(res.Added)
	sortFindings(res.Resolved)
	sortFindings(res.NewlyReachable)
	sortSeverityChanges(res.SeverityUp)
	sortSeverityChanges(res.SeverityDown)
	sortPaths(res.AddedPaths)
	sortPaths(res.RemovedPaths)
	return res
}

// becameReachable reports a transition into the reachable state. A finding that
// was unknown or not-reachable and is now reachable is a freshly-opened
// exposure; a finding that was already reachable is not re-flagged.
func becameReachable(from, to findings.Reachability) bool {
	return to == findings.ReachYes && from != findings.ReachYes
}

func indexFindings(fs []findings.Finding) map[string]findings.Finding {
	m := make(map[string]findings.Finding, len(fs))
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func indexPaths(ps []graph.Path) map[string]graph.Path {
	m := make(map[string]graph.Path, len(ps))
	for _, p := range ps {
		m[p.ID] = p
	}
	return m
}

func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ar, br := a.Severity.Rank(), b.Severity.Rank(); ar != br {
			return ar > br
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.ID < b.ID
	})
}

func sortSeverityChanges(cs []SeverityChange) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if ar, br := a.To.Rank(), b.To.Rank(); ar != br {
			return ar > br
		}
		return a.Finding.ID < b.Finding.ID
	})
}

func sortPaths(ps []graph.Path) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Score != ps[j].Score {
			return ps[i].Score > ps[j].Score
		}
		return ps[i].ID < ps[j].ID
	})
}
