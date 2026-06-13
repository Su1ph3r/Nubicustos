package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decode(t *testing.T, rec *httptest.ResponseRecorder) (int, map[string]any) {
	t.Helper()
	var v map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("bad json: %v\n%s", err, rec.Body)
		}
	}
	return rec.Code, v
}

func opServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := seededServer(t)
	s.mode = ModeOperator
	s.token = "tok-secret"
	return s, s.token
}

func do(s *Server, method, path string, header map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, nil)
	for k, v := range header {
		r.Header.Set(k, v)
	}
	s.Handler().ServeHTTP(rec, r)
	return rec
}

// --- job mechanics ---------------------------------------------------------

func TestJobFanoutAndTerminal(t *testing.T) {
	j := &job{id: "j1", kind: "tool", status: jobRunning}
	backlog, live := j.subscribe()
	if len(backlog) != 0 || live == nil {
		t.Fatalf("a fresh job should have empty backlog and a live channel")
	}
	j.emitLog("starting")
	j.finishDone([]string{"scan-x"}, "1 ran")

	var names []string
	for e := range live { // closed after the terminal event
		names = append(names, e.name)
	}
	if len(names) < 2 || names[len(names)-1] != "done" {
		t.Fatalf("subscriber should receive events ending in done, got %v", names)
	}
	if snap := j.snapshot(); snap["status"] != jobDone {
		t.Fatalf("status should be done, got %v", snap["status"])
	}
}

func TestJobLateSubscriberGetsBacklogNoLive(t *testing.T) {
	j := &job{id: "j2", kind: "tool", status: jobRunning}
	j.emitLog("a")
	j.finishDone(nil, "done")
	backlog, live := j.subscribe()
	if live != nil {
		t.Fatal("a terminal job must not hand out a live channel")
	}
	if len(backlog) < 2 || backlog[len(backlog)-1].name != "done" {
		t.Fatalf("late subscriber should get the full backlog incl. done, got %d events", len(backlog))
	}
}

func TestJobCancelInvokesCancelFunc(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := newJobManager()
	j := m.create("tool", cancel)
	got, ok := m.get(j.id)
	if !ok || got != j {
		t.Fatal("manager should return the created job")
	}
	j.cancel()
	if ctx.Err() == nil {
		t.Fatal("cancel should cancel the job context")
	}
}

// --- HTTP: mode gating + token ---------------------------------------------

func TestOperatorRoutesAbsentInReadOnly(t *testing.T) {
	s := seededServer(t) // read-only
	if rec := do(s, http.MethodPost, "/api/v1/tools/run", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("operator route must be absent (404) in read-only mode, got %d", rec.Code)
	}
}

func TestTokenGate(t *testing.T) {
	s, tok := opServer(t)
	if rec := do(s, http.MethodGet, "/api/v1/meta", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("operator API without a token should be 401, got %d", rec.Code)
	}
	if rec := do(s, http.MethodGet, "/api/v1/meta", map[string]string{"Authorization": "Bearer " + tok}); rec.Code != http.StatusOK {
		t.Fatalf("operator API with a valid bearer token should be 200, got %d", rec.Code)
	}
	if rec := do(s, http.MethodGet, "/api/v1/meta?t="+tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("the t= query token (for EventSource) should be accepted, got %d", rec.Code)
	}
	if rec := do(s, http.MethodGet, "/api/v1/meta?t=wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong token should be 401, got %d", rec.Code)
	}
}

func TestMetaCapabilitiesInOperatorMode(t *testing.T) {
	s, tok := opServer(t)
	_, v := getJSON(t, s, "/api/v1/meta?t="+tok)
	if v["mode"] != "operator" {
		t.Fatalf("mode should be operator, got %v", v["mode"])
	}
	caps := map[string]bool{}
	for _, c := range v["capabilities"].([]any) {
		caps[c.(string)] = true
	}
	for _, want := range []string{"scan.run", "tools.run", "preflight.run", "auth"} {
		if !caps[want] {
			t.Fatalf("operator should advertise %q, got %v", want, v["capabilities"])
		}
	}
}

// --- HTTP: full tools-run → SSE → done -------------------------------------

func TestToolsRunStreamsToDone(t *testing.T) {
	s, tok := opServer(t)
	auth := map[string]string{"Authorization": "Bearer " + tok}

	// Start a sweep. No external tools are installed in the test environment, so
	// the job completes quickly with everything skipped — exercising the full
	// job + SSE machinery without needing real binaries.
	rec := do(s, http.MethodPost, "/api/v1/tools/run", auth)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("tools/run should accept the job (202), got %d: %s", rec.Code, rec.Body)
	}
	_, v := decode(t, rec)
	jobID, _ := v["job_id"].(string)
	if jobID == "" {
		t.Fatalf("expected a job_id, got %v", v)
	}

	// Stream events: a terminal job replays its backlog and returns; a running
	// one blocks until the terminal event closes the channel. Either way the
	// stream must end in a done event.
	stream := do(s, http.MethodGet, "/api/v1/jobs/"+jobID+"/events?t="+tok, nil)
	if stream.Code != http.StatusOK {
		t.Fatalf("SSE events status %d", stream.Code)
	}
	body := stream.Body.String()
	if !strings.Contains(body, "event: done") {
		t.Fatalf("event stream should end in a done event:\n%s", body)
	}

	if rec := do(s, http.MethodGet, "/api/v1/jobs/"+jobID, auth); !strings.Contains(rec.Body.String(), `"status":"done"`) {
		t.Fatalf("job status should be done, got %s", rec.Body)
	}
	if rec := do(s, http.MethodGet, "/api/v1/jobs/nope", auth); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown job should 404, got %d", rec.Code)
	}
}
