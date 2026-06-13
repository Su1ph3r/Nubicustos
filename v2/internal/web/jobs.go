package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/progress"
)

// Job status values.
const (
	jobRunning   = "running"
	jobDone      = "done"
	jobError     = "error"
	jobCancelled = "cancelled"
)

// sseEvent is one server-sent event: an event name (phase|log|done|error) and a
// JSON-serializable payload.
type sseEvent struct {
	name string
	data any
}

// job is a running (or finished) operator action with live progress. Events are
// buffered in history so a late SSE subscriber gets the full backlog, then
// streamed live to each subscriber. A job is terminal after a done/error event.
type job struct {
	id   string
	kind string // "scan" | "tool"

	mu         sync.Mutex
	status     string
	phase      string
	done       int
	total      int
	scanIDs    []string
	errMsg     string
	startedAt  time.Time
	finishedAt time.Time
	history    []sseEvent
	subs       []chan sseEvent
	closed     bool

	cancel context.CancelFunc
}

// emit appends an event to history, updates the status snapshot, and fans it out
// to current subscribers. A done/error event makes the job terminal and closes
// subscriber channels. Safe for concurrent callers.
func (j *job) emit(e sseEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	j.history = append(j.history, e)

	switch e.name {
	case "phase":
		if m, ok := e.data.(map[string]any); ok {
			if p, ok := m["phase"].(string); ok {
				j.phase = p
			}
			if d, ok := m["done"].(int); ok {
				j.done = d
			}
			if t, ok := m["total"].(int); ok {
				j.total = t
			}
		}
	case "done":
		j.status, j.finishedAt, j.closed = jobDone, time.Now().UTC(), true
		if m, ok := e.data.(map[string]any); ok {
			if ids, ok := m["scan_ids"].([]string); ok {
				j.scanIDs = ids
			}
		}
	case "error":
		// Honor the terminal status carried in the payload (error vs cancelled);
		// don't hardcode jobError, or a cancelled job would report "error".
		st := jobError
		if m, ok := e.data.(map[string]any); ok {
			if s, ok := m["status"].(string); ok && s != "" {
				st = s
			}
			if msg, ok := m["message"].(string); ok {
				j.errMsg = msg
			}
		}
		j.status, j.finishedAt, j.closed = st, time.Now().UTC(), true
	}

	for _, ch := range j.subs {
		select {
		case ch <- e:
		default: // a slow subscriber loses the live copy but has history on reconnect
		}
	}
	if j.closed {
		for _, ch := range j.subs {
			close(ch)
		}
		j.subs = nil
	}
}

// emitPhase reports a progress.Event as a "phase" SSE event.
func (j *job) emitPhase(e progress.Event) {
	j.emit(sseEvent{name: "phase", data: map[string]any{
		"phase": string(e.Phase), "done": e.Done, "total": e.Total, "detail": e.Detail,
	}})
}

func (j *job) emitLog(line string) {
	j.emit(sseEvent{name: "log", data: map[string]any{"message": line}})
}

func (j *job) finishDone(scanIDs []string, summary string) {
	j.emit(sseEvent{name: "done", data: map[string]any{"status": jobDone, "scan_ids": scanIDs, "summary": summary}})
}

func (j *job) finishError(status, message string) {
	// emit records the terminal status (error|cancelled) from the payload.
	j.emit(sseEvent{name: "error", data: map[string]any{"status": status, "message": message}})
}

// unsubscribe removes ch from the live subscriber set (called when an SSE client
// disconnects, so the producer stops sending to a dead channel).
func (j *job) unsubscribe(ch chan sseEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i, c := range j.subs {
		if c == ch {
			j.subs = append(j.subs[:i], j.subs[i+1:]...)
			return
		}
	}
}

// terminalEvent reconstructs the terminal SSE event from the authoritative
// status snapshot. Used when the live channel closed without the consumer
// having seen a done/error frame (a dropped terminal event), so a connected
// client never mistakes a finished/failed job for one still running.
func (j *job) terminalEvent() (sseEvent, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch j.status {
	case jobDone:
		return sseEvent{name: "done", data: map[string]any{"status": jobDone, "scan_ids": j.scanIDs}}, true
	case jobError, jobCancelled:
		return sseEvent{name: "error", data: map[string]any{"status": j.status, "message": j.errMsg}}, true
	default:
		return sseEvent{}, false
	}
}

// subscribe returns the event backlog and, if the job is still running, a
// channel for live events (nil when already terminal).
func (j *job) subscribe() (backlog []sseEvent, live chan sseEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	backlog = append([]sseEvent(nil), j.history...)
	if j.closed {
		return backlog, nil
	}
	live = make(chan sseEvent, 128)
	j.subs = append(j.subs, live)
	return backlog, live
}

// snapshot returns the job's current status for the polling endpoint.
func (j *job) snapshot() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := map[string]any{
		"job_id":   j.id,
		"kind":     j.kind,
		"status":   j.status,
		"phase":    j.phase,
		"progress": map[string]int{"done": j.done, "total": j.total},
		"scan_ids": j.scanIDs,
	}
	if !j.startedAt.IsZero() {
		m["started_at"] = j.startedAt.UTC().Format(time.RFC3339)
	}
	if !j.finishedAt.IsZero() {
		m["finished_at"] = j.finishedAt.UTC().Format(time.RFC3339)
	}
	if j.errMsg != "" {
		m["error"] = j.errMsg
	}
	return m
}

// jobManager holds running and recently-finished jobs.
type jobManager struct {
	mu   sync.Mutex
	jobs map[string]*job
}

func newJobManager() *jobManager { return &jobManager{jobs: map[string]*job{}} }

func (m *jobManager) create(kind string, cancel context.CancelFunc) *job {
	j := &job{id: newJobID(), kind: kind, status: jobRunning, startedAt: time.Now().UTC(), cancel: cancel}
	m.mu.Lock()
	m.jobs[j.id] = j
	m.mu.Unlock()
	return j
}

// guard runs a job body, converting a panic into a terminal error event. This
// guarantees the job reaches a terminal state (never stuck "running" with SSE
// subscribers blocked) and stops a panic in one job from crashing the server.
func (j *job) guard(fn func()) {
	defer func() {
		if v := recover(); v != nil {
			j.finishError(jobError, fmt.Sprintf("internal error: %v", v))
		}
	}()
	fn()
}

func (m *jobManager) get(id string) (*job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	return j, ok
}

func newJobID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "job-" + hex.EncodeToString(b[:])
}

// newScanID returns a sortable, collision-resistant scan id (store lists order
// by started_at then id, so the timestamp prefix keeps newest-first stable).
func newScanID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "scan-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}
