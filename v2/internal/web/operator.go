package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/plugins"
	"github.com/Su1ph3r/nubicustos/internal/progress"
)

// routesOperator registers the operator-mode action routes. These are mounted
// only in operator mode, so in read-only mode they do not exist (404) — a
// shared instance can never reach them.
func (s *Server) routesOperator(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tools/run", s.handleToolsRun)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleJobStatus)
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.handleJobEvents)
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", s.handleJobCancel)
	mux.HandleFunc("GET /api/v1/auth", s.handleAuthStatus)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("POST /api/v1/scans/run", s.handleScanRun)
	mux.HandleFunc("POST /api/v1/preflight/run", s.handlePreflightRun)
}

// tokenGate enforces the session token on every /api request in operator mode.
// The token is accepted as `Authorization: Bearer <t>` or, for the SSE endpoint
// (EventSource cannot set headers), the `t` query parameter. Requiring a token
// the page was handed out-of-band also defeats cross-site requests: a forged
// page cannot read the local token, and a custom Authorization header would
// trip a CORS preflight this same-origin server never grants.
func (s *Server) tokenGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.validToken(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid session token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) validToken(r *http.Request) bool {
	got := r.URL.Query().Get("t")
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		got = strings.TrimPrefix(h, "Bearer ")
	}
	return s.token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// handleToolsRun starts a background tool sweep and returns its job id. Body:
// { "tool": "trivy"|"", "target": ".", "concurrency": 4 }. An empty/absent tool
// runs every installed tool.
func (s *Server) handleToolsRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tool        string `json:"tool"`
		Target      string `json:"target"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.Target == "" {
		req.Target = "."
	}
	if strings.HasPrefix(req.Target, "-") {
		writeError(w, http.StatusBadRequest, "invalid_target", "target must not start with '-'")
		return
	}
	if req.Concurrency <= 0 {
		req.Concurrency = plugins.DefaultSweepConcurrency
	}

	ctx, cancel := context.WithCancel(context.Background())
	j := s.jobs.create("tool", cancel)
	go s.runToolsJob(ctx, j, req.Tool, req.Target, req.Concurrency)

	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.id, "kind": "tool", "status": jobRunning})
}

// runToolsJob runs the sweep with live progress and persists each tool's
// findings as a scan, emitting a terminal done (or error on cancellation).
func (s *Server) runToolsJob(ctx context.Context, j *job, tool, target string, concurrency int) {
	reporter := progress.Func(j.emitPhase)

	var results []plugins.RunResult
	if tool == "" {
		results = plugins.RunAvailableWithProgress(ctx, target, concurrency, reporter)
	} else {
		m, ok := plugins.Lookup(tool)
		if !ok {
			j.finishError(jobError, "unknown tool "+tool)
			return
		}
		c := progress.NewCounter(reporter, progress.PhaseTools, 1)
		fs, err := plugins.Run(ctx, m, target)
		c.Done(m.Name)
		results = []plugins.RunResult{{Manifest: m, Findings: fs, Err: err, Available: true, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}}
	}

	var ran, skipped, failed, total int
	var scanIDs []string
	for _, res := range results {
		switch {
		case !res.Available:
			skipped++
			j.emitLog(res.Manifest.Name + ": skipped (not installed)")
		case res.Err != nil:
			failed++
			j.emitLog(res.Manifest.Name + ": error: " + res.Err.Error())
		default:
			ran++
			total += len(res.Findings)
			id, err := s.persistPluginScan(ctx, res, target)
			if err != nil {
				j.finishError(jobError, "persisting "+res.Manifest.Name+": "+err.Error())
				return
			}
			scanIDs = append(scanIDs, id)
			j.emitLog(fmt.Sprintf("%s: %d finding(s) (scan %s)", res.Manifest.Name, len(res.Findings), id))
		}
	}

	if ctx.Err() != nil {
		j.finishError(jobCancelled, "cancelled")
		return
	}
	j.finishDone(scanIDs, fmt.Sprintf("%d ran, %d skipped, %d failed — %d finding(s)", ran, skipped, failed, total))
}

// persistPluginScan stores one tool's findings as a plugin:<tool> scan.
func (s *Server) persistPluginScan(ctx context.Context, res plugins.RunResult, target string) (string, error) {
	id := newScanID()
	if err := s.store.CreateScan(ctx, id, "plugin:"+res.Manifest.Name, target, res.Manifest.Binary, res.StartedAt); err != nil {
		return "", err
	}
	if err := s.store.SaveFindings(ctx, id, res.Findings, res.FinishedAt); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	j, ok := s.jobs.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "job_not_found", "no job "+r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, j.snapshot())
}

func (s *Server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	j, ok := s.jobs.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "job_not_found", "no job "+r.PathValue("id"))
		return
	}
	if j.cancel != nil {
		j.cancel()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.id, "status": "cancelling"})
}

// handleJobEvents streams the job's events as SSE: the buffered backlog first,
// then live events until the job is terminal or the client disconnects.
func (s *Server) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	j, ok := s.jobs.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "job_not_found", "no job "+r.PathValue("id"))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "no_stream", "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	backlog, live := j.subscribe()
	for _, e := range backlog {
		writeSSE(w, e)
	}
	flusher.Flush()
	if live == nil {
		return // already terminal; backlog was the whole story
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return // client disconnected
		case e, open := <-live:
			if !open {
				return // job terminal; channel closed after the final event
			}
			writeSSE(w, e)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": keep-alive\n\n") // comment frame; keeps proxies from idling out
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, e sseEvent) {
	b, err := json.Marshal(e.data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.name, b)
}
