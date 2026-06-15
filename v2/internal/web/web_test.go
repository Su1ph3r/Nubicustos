package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

func seededServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	now := time.Now().UTC()
	if err := st.CreateScan(context.Background(), "scan-1", "aws", "123456789012", "arn:aws:iam::123456789012:user/op", now); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	fs := []findings.Finding{
		{
			ID: "aws_s3_public_access::b1", CheckID: "aws_s3_public_access", Title: "S3 public",
			Severity: findings.SeverityHigh, Status: findings.StatusOpen, Provider: "aws", Service: "s3",
			Resource:  findings.Resource{ID: "b1", Type: "aws_s3_bucket", Region: "us-east-1", Account: "123456789012"},
			Reachable: findings.ReachYes, FirstSeen: now, LastSeen: now,
			Evidence: []findings.Evidence{{Vantage: findings.VantageExternal, Request: "GET …", Response: "HTTP 200", Verdict: "confirmed", CapturedAt: now}},
		},
		{
			ID: "aws_iam_root_mfa_disabled::acct", CheckID: "aws_iam_root_mfa_disabled", Title: "Root MFA off",
			Severity: findings.SeverityCritical, Status: findings.StatusOpen, Provider: "aws", Service: "iam",
			Resource:  findings.Resource{ID: "acct", Type: "aws_account", Account: "123456789012"},
			Reachable: findings.ReachUnknown, FirstSeen: now, LastSeen: now,
		},
	}
	if err := st.SaveFindings(context.Background(), "scan-1", fs, now); err != nil {
		t.Fatalf("save findings: %v", err)
	}
	return New(st, ModeReadOnly, "v-test", "")
}

func get(t *testing.T, s *Server, path string) (*http.Response, []byte) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Result(), rec.Body.Bytes()
}

func getJSON(t *testing.T, s *Server, path string) (int, map[string]any) {
	t.Helper()
	resp, body := get(t, s, path)
	var v map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("%s: bad json: %v\n%s", path, err, body)
		}
	}
	return resp.StatusCode, v
}

func TestMetaReportsReadOnlyMode(t *testing.T) {
	code, v := getJSON(t, seededServer(t), "/api/v1/meta")
	if code != 200 {
		t.Fatalf("meta status %d", code)
	}
	if v["mode"] != "read-only" {
		t.Fatalf("mode should be read-only, got %v", v["mode"])
	}
	if caps, _ := v["capabilities"].([]any); len(caps) != 0 {
		t.Fatalf("read-only mode must advertise no capabilities, got %v", v["capabilities"])
	}
}

func TestScansListAndGetAndLatest(t *testing.T) {
	s := seededServer(t)
	if code, v := getJSON(t, s, "/api/v1/scans"); code != 200 || v["total"].(float64) != 1 {
		t.Fatalf("scans list: code=%d total=%v", code, v["total"])
	}
	if code, v := getJSON(t, s, "/api/v1/scans/scan-1"); code != 200 || v["provider"] != "aws" {
		t.Fatalf("scan get: code=%d provider=%v", code, v["provider"])
	}
	if code, v := getJSON(t, s, "/api/v1/scans/latest"); code != 200 || v["id"] != "scan-1" {
		t.Fatalf("latest should resolve to scan-1, got code=%d id=%v", code, v["id"])
	}
	if code, _ := getJSON(t, s, "/api/v1/scans/nope"); code != 404 {
		t.Fatalf("unknown scan should 404, got %d", code)
	}
}

func TestSummaryCounts(t *testing.T) {
	code, v := getJSON(t, seededServer(t), "/api/v1/scans/scan-1/summary")
	if code != 200 {
		t.Fatalf("summary status %d", code)
	}
	sev := v["severity"].(map[string]any)
	if sev["critical"].(float64) != 1 || sev["high"].(float64) != 1 {
		t.Fatalf("severity tally wrong: %v", sev)
	}
	reach := v["reachability"].(map[string]any)
	if reach["reachable"].(float64) != 1 || reach["unknown"].(float64) != 1 {
		t.Fatalf("reachability tally wrong: %v", reach)
	}
}

func TestFindingsFiltersSortPaginate(t *testing.T) {
	s := seededServer(t)

	// default sort: critical first
	_, v := getJSON(t, s, "/api/v1/scans/scan-1/findings")
	if v["total"].(float64) != 2 {
		t.Fatalf("expected 2 findings, got %v", v["total"])
	}
	data := v["data"].([]any)
	if first := data[0].(map[string]any); first["severity"] != "critical" {
		t.Fatalf("default sort should put critical first, got %v", first["severity"])
	}

	cases := []struct {
		q     string
		total float64
	}{
		{"?severity=high", 1},
		{"?service=iam", 1},
		{"?provider=aws", 2},
		{"?reachable=reachable", 1},
		{"?reachable=not_reachable", 0},
		{"?has_evidence=true", 1},
	}
	for _, c := range cases {
		_, v := getJSON(t, s, "/api/v1/scans/scan-1/findings"+c.q)
		if v["total"].(float64) != c.total {
			t.Fatalf("findings%s: expected total %v, got %v", c.q, c.total, v["total"])
		}
	}

	// pagination: limit caps the page but total reflects the full filtered set
	_, v = getJSON(t, s, "/api/v1/scans/scan-1/findings?limit=1")
	if len(v["data"].([]any)) != 1 || v["total"].(float64) != 2 {
		t.Fatalf("limit=1 should return 1 of 2, got data=%d total=%v", len(v["data"].([]any)), v["total"])
	}
}

func TestFindingByIDAndNotFound(t *testing.T) {
	s := seededServer(t)
	code, v := getJSON(t, s, "/api/v1/scans/scan-1/findings/aws_s3_public_access::b1")
	if code != 200 || v["check_id"] != "aws_s3_public_access" {
		t.Fatalf("finding get: code=%d check_id=%v", code, v["check_id"])
	}
	if code, _ := getJSON(t, s, "/api/v1/scans/scan-1/findings/nope"); code != 404 {
		t.Fatalf("unknown finding should 404, got %d", code)
	}
}

func TestServicesAndPathsAndTools(t *testing.T) {
	s := seededServer(t)
	_, v := getJSON(t, s, "/api/v1/scans/scan-1/services")
	got := map[string]bool{}
	for _, x := range v["data"].([]any) {
		got[x.(string)] = true
	}
	if !got["s3"] || !got["iam"] {
		t.Fatalf("services should include s3 and iam, got %v", v["data"])
	}
	if code, v := getJSON(t, s, "/api/v1/scans/scan-1/paths"); code != 200 || v["total"].(float64) != 0 {
		t.Fatalf("no graph saved → 0 paths, got code=%d total=%v", code, v["total"])
	}
	if code, v := getJSON(t, s, "/api/v1/tools"); code != 200 || v["total"].(float64) == 0 {
		t.Fatalf("tools should list the built-in catalog, got code=%d total=%v", code, v["total"])
	}
}

func TestExportCairnAndBadFormat(t *testing.T) {
	s := seededServer(t)
	resp, body := get(t, s, "/api/v1/scans/scan-1/export/cairn")
	if resp.StatusCode != 200 {
		t.Fatalf("export cairn status %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("export should be a download, got %q", cd)
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("cairn export should be valid JSON: %v", err)
	}
	if code, _ := getJSON(t, s, "/api/v1/scans/scan-1/export/bogus"); code != 400 {
		t.Fatalf("unknown export format should 400, got %d", code)
	}
}

func TestPreflightNotYetPersisted(t *testing.T) {
	if code, _ := getJSON(t, seededServer(t), "/api/v1/preflight"); code != 404 {
		t.Fatalf("preflight should 404 until persisted, got %d", code)
	}
}

func TestSPAServesShellAtRoot(t *testing.T) {
	resp, body := get(t, seededServer(t), "/")
	if resp.StatusCode != 200 {
		t.Fatalf("root status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "nubicustos") {
		t.Fatalf("root should serve the SPA shell, got:\n%s", body)
	}
}

func TestSPADeepLinkFallsBackToShell(t *testing.T) {
	// A client-side route (no file extension) should serve the shell, not 404.
	resp, body := get(t, seededServer(t), "/findings")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "nubicustos") {
		t.Fatalf("deep link should fall back to the shell, got %d:\n%s", resp.StatusCode, body)
	}
}
