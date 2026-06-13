package web

import (
	"net/http"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

func TestAuthStatusNoneAndLogout(t *testing.T) {
	s, tok := opServer(t)
	auth := map[string]string{"Authorization": "Bearer " + tok}

	code, v := decode(t, do(s, http.MethodGet, "/api/v1/auth", auth))
	if code != 200 || v["status"] != "none" {
		t.Fatalf("no session → status none, got code=%d status=%v", code, v["status"])
	}
	if rec := do(s, http.MethodPost, "/api/v1/auth/logout", auth); rec.Code != http.StatusNoContent {
		t.Fatalf("logout should be 204, got %d", rec.Code)
	}
}

func TestAuthStatusReflectsInjectedSession(t *testing.T) {
	s, tok := opServer(t)
	s.sess = session{present: true, account: "123456789012", identity: "arn:aws:iam::123456789012:user/op", method: "default-chain"}
	_, v := decode(t, do(s, http.MethodGet, "/api/v1/auth", map[string]string{"Authorization": "Bearer " + tok}))
	if v["status"] != "active" || v["account"] != "123456789012" {
		t.Fatalf("active session should be reported, got %v", v)
	}
}

func TestScanRunRequiresSession(t *testing.T) {
	s, tok := opServer(t)
	if rec := do(s, http.MethodPost, "/api/v1/scans/run", map[string]string{"Authorization": "Bearer " + tok}); rec.Code != http.StatusConflict {
		t.Fatalf("scan run without a session should be 409, got %d", rec.Code)
	}
}

func TestPreflightRunRequiresSession(t *testing.T) {
	s, tok := opServer(t)
	if rec := do(s, http.MethodPost, "/api/v1/preflight/run", map[string]string{"Authorization": "Bearer " + tok}); rec.Code != http.StatusConflict {
		t.Fatalf("preflight run without a session should be 409, got %d", rec.Code)
	}
}

// TestScanRunJobCompletes injects a session and runs a scan job. The web test
// binary registers no collectors/checks (those init in other packages), so the
// engine run is empty and instant — exercising the full scan-job + SSE + persist
// plumbing deterministically, without cloud calls.
func TestScanRunJobCompletes(t *testing.T) {
	s, tok := opServer(t)
	auth := map[string]string{"Authorization": "Bearer " + tok}
	s.sess = session{present: true, account: "123456789012", identity: "arn:aws:iam::123456789012:role/op", method: "default-chain", cfg: awssdk.Config{}}

	rec := do(s, http.MethodPost, "/api/v1/scans/run", auth)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scan run should accept the job (202), got %d: %s", rec.Code, rec.Body)
	}
	_, v := decode(t, rec)
	jobID, _ := v["job_id"].(string)
	if jobID == "" {
		t.Fatalf("expected a job_id, got %v", v)
	}

	stream := do(s, http.MethodGet, "/api/v1/jobs/"+jobID+"/events?t="+tok, nil)
	if !strings.Contains(stream.Body.String(), "event: done") {
		t.Fatalf("scan job event stream should end in done:\n%s", stream.Body)
	}
	if rec := do(s, http.MethodGet, "/api/v1/jobs/"+jobID, auth); !strings.Contains(rec.Body.String(), `"status":"done"`) {
		t.Fatalf("scan job status should be done, got %s", rec.Body)
	}
	// The completed scan should now be the latest and browsable.
	if code, _ := getJSONTok(t, s, "/api/v1/scans/latest", tok); code != 200 {
		t.Fatalf("the persisted scan should resolve as latest, got %d", code)
	}
}

func getJSONTok(t *testing.T, s *Server, path, tok string) (int, map[string]any) {
	t.Helper()
	return decode(t, do(s, http.MethodGet, path, map[string]string{"Authorization": "Bearer " + tok}))
}
