// Package progress carries real, backend-sourced scan progress to any frontend
// (the CLI status line, the TUI launcher, the web SSE stream). The cardinal
// rule it exists to enforce: progress is only ever reported when work has
// actually completed — there is no timer-driven animation. A phase with a known
// denominator reports done/total; a phase whose total cannot be known up front
// reports Total == 0 (indeterminate), and the frontend shows activity, not a
// fabricated percentage.
package progress

import "sync/atomic"

// Phase identifies a stage of work in a scan or tool sweep.
type Phase string

const (
	PhaseAuth         Phase = "authenticating"
	PhaseDiscover     Phase = "enumerating-scope" // regions / subscriptions / projects
	PhaseCollect      Phase = "collecting"
	PhaseCheck        Phase = "running-checks"
	PhaseReachability Phase = "solving-reachability"
	PhaseGraph        Phase = "building-graph"
	PhaseValidate     Phase = "active-validation"
	PhasePersist      Phase = "persisting"
	PhaseTools        Phase = "running-tools" // external-tool sweep
)

// Event is one progress update. Done/Total describe the current phase's
// countable units; Total == 0 means the phase is indeterminate (no knowable
// denominator) — render it as activity, never as a percentage. Detail names the
// unit the update concerns (a collector, a tool, a region), for a live label.
type Event struct {
	Phase  Phase  `json:"phase"`
	Done   int    `json:"done"`
	Total  int    `json:"total"`
	Detail string `json:"detail,omitempty"`
}

// Indeterminate reports whether this event's phase has no knowable total.
func (e Event) Indeterminate() bool { return e.Total <= 0 }

// Reporter receives progress events. Implementations MUST be safe for
// concurrent calls — a scan emits from a bounded worker pool. A nil Reporter is
// valid and means "no progress wanted"; use the package Report helper or a
// Counter, both of which are nil-safe.
type Reporter interface {
	Report(Event)
}

// Func adapts a plain function to a Reporter.
type Func func(Event)

// Report implements Reporter; a nil Func is a no-op.
func (f Func) Report(e Event) {
	if f != nil {
		f(e)
	}
}

// Report sends e to r if r is non-nil.
func Report(r Reporter, e Event) {
	if r != nil {
		r.Report(e)
	}
}

// Phase announces the start of an indeterminate phase (Total 0) on r.
func ReportPhase(r Reporter, p Phase, detail string) {
	Report(r, Event{Phase: p, Detail: detail})
}

// Counter emits incremental progress for a phase with a known total. It
// announces the phase (0/total) at construction, then one done/total event per
// Done call. Safe for concurrent use: each Done advances the count atomically.
// A nil *Counter is a no-op, so callers need not branch on whether progress is
// wanted.
type Counter struct {
	r     Reporter
	phase Phase
	total int
	done  int32
}

// NewCounter announces phase at 0/total on r and returns a counter for it.
func NewCounter(r Reporter, phase Phase, total int) *Counter {
	Report(r, Event{Phase: phase, Done: 0, Total: total})
	return &Counter{r: r, phase: phase, total: total}
}

// Done records one completed unit and reports the new done/total. detail names
// the unit just completed.
func (c *Counter) Done(detail string) {
	if c == nil {
		return
	}
	d := atomic.AddInt32(&c.done, 1)
	Report(c.r, Event{Phase: c.phase, Done: int(d), Total: c.total, Detail: detail})
}
