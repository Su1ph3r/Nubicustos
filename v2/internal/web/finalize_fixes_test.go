package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// A cancelled job must report status "cancelled", not "error" — the snapshot
// (polling) and the SSE payload must agree.
func TestCancelledJobReportsCancelled(t *testing.T) {
	j := &job{id: "jc", kind: "tool", status: jobRunning}
	j.finishError(jobCancelled, "cancelled")
	if got := j.snapshot()["status"]; got != jobCancelled {
		t.Fatalf("cancelled job snapshot status should be %q, got %v", jobCancelled, got)
	}
	ev, ok := j.terminalEvent()
	if !ok || ev.name != "error" {
		t.Fatalf("terminal event should be an error frame, got %+v", ev)
	}
	if ev.data.(map[string]any)["status"] != jobCancelled {
		t.Fatalf("terminal event status should be cancelled, got %v", ev.data)
	}
}

func TestErrorJobReportsError(t *testing.T) {
	j := &job{id: "je", kind: "scan", status: jobRunning}
	j.finishError(jobError, "boom")
	if got := j.snapshot()["status"]; got != jobError {
		t.Fatalf("errored job status should be %q, got %v", jobError, got)
	}
}

// A panic inside a guarded job body becomes a terminal error — the job never
// stays stuck "running".
func TestGuardConvertsPanicToTerminalError(t *testing.T) {
	j := &job{id: "jp", kind: "tool", status: jobRunning}
	done := make(chan struct{})
	go func() { defer close(done); j.guard(func() { panic("kaboom") }) }()
	<-done
	snap := j.snapshot()
	if snap["status"] != jobError {
		t.Fatalf("a panicking job should end as error, got %v", snap["status"])
	}
	if e := snap["error"]; e == nil || !strings.Contains(e.(string), "kaboom") {
		t.Fatalf("the panic value should be surfaced, got %v", e)
	}
}

// terminalEvent reconstructs a done frame from the snapshot for a completed job
// (covers the dropped-terminal-frame recovery path).
func TestTerminalEventForDone(t *testing.T) {
	j := &job{id: "jd", kind: "scan", status: jobRunning}
	j.finishDone([]string{"scan-z"}, "done")
	ev, ok := j.terminalEvent()
	if !ok || ev.name != "done" {
		t.Fatalf("expected a done terminal event, got %+v ok=%v", ev, ok)
	}
	ids, _ := ev.data.(map[string]any)["scan_ids"].([]string)
	if len(ids) != 1 || ids[0] != "scan-z" {
		t.Fatalf("terminal done should carry the scan ids, got %v", ev.data)
	}
}

// Any unmatched /api path (not just /api/v1) must be a JSON 404, never the SPA.
func TestUnknownAPIPathsAre404NotSPA(t *testing.T) {
	s := seededServer(t)
	for _, p := range []string{"/api/foo", "/api/v2/scans", "/api/v1/bogus"} {
		resp, body := get(t, s, p)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s should 404, got %d", p, resp.StatusCode)
		}
		if strings.Contains(string(body), "<html") || strings.Contains(string(body), "<!doctype") {
			t.Fatalf("%s must return JSON, not the SPA shell:\n%s", p, body)
		}
		if !strings.Contains(string(body), `"error"`) {
			t.Fatalf("%s should return a JSON error envelope, got %s", p, body)
		}
	}
}

// When the credential's expiry can't be determined, the status must say so
// rather than implying a non-expiring session.
func TestAuthStatusSurfacesUnknownExpiry(t *testing.T) {
	s, tok := opServer(t)
	s.sess = session{present: true, account: "123", identity: "arn", method: "default-chain", expiryKnown: false}
	_, v := decode(t, do(s, http.MethodGet, "/api/v1/auth", map[string]string{"Authorization": "Bearer " + tok}))
	if v["status"] != "active" || v["expiry"] != "unknown" {
		t.Fatalf("unknown expiry should be surfaced, got %v", v)
	}
	// A known non-expiring session should NOT carry the unknown marker.
	s.sess = session{present: true, account: "123", identity: "arn", method: "instance-role", expiryKnown: true}
	_, v = decode(t, do(s, http.MethodGet, "/api/v1/auth", map[string]string{"Authorization": "Bearer " + tok}))
	if _, has := v["expiry"]; has {
		t.Fatalf("a known (non-expiring) session must not be marked unknown, got %v", v)
	}
}

// DeleteScan removes the scan and its findings so an orphaned row can't be
// listed as a clean empty scan.
func TestStoreDeleteScanRemovesScan(t *testing.T) {
	s := seededServer(t)
	if err := s.store.DeleteScan(context.Background(), "scan-1"); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	if code, _ := getJSON(t, s, "/api/v1/scans"); code != 200 {
		t.Fatalf("scans list status %d", code)
	}
	_, v := getJSON(t, s, "/api/v1/scans")
	if v["total"].(float64) != 0 {
		t.Fatalf("after delete, no scans should remain, got total=%v", v["total"])
	}
	if code, _ := getJSON(t, s, "/api/v1/scans/scan-1"); code != 404 {
		t.Fatalf("the deleted scan should 404, got %d", code)
	}
}
