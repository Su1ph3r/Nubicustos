package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

// seed returns a store with one scan holding two findings and one attack path.
func seed(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Date(2026, 6, 11, 9, 0, 0, 0, time.UTC)
	if err := st.CreateScan(ctx, "s1", "aws", "111122223333", "arn:auditor", now); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	fs := []findings.Finding{
		{ID: "f-crit", CheckID: "aws_iam_root_mfa_disabled", Title: "root mfa off", Severity: findings.SeverityCritical, Status: findings.StatusOpen, Provider: "aws", Service: "iam", Resource: findings.Resource{ID: "account:1"}},
		{ID: "f-high", CheckID: "aws_s3_public_access", Title: "public bucket", Severity: findings.SeverityHigh, Status: findings.StatusOpen, Provider: "aws", Service: "s3", Resource: findings.Resource{ID: "b1"}, Remediation: "block it"},
	}
	if err := st.SaveFindings(ctx, "s1", fs, now); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}
	g := &graph.Graph{Paths: []graph.Path{{ID: "p1", Title: "exposed db", Score: 64, Severity: findings.SeverityHigh}}}
	if err := st.SaveGraph(ctx, "s1", g); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}
	return st, ctx
}

func call(args map[string]any) mcp.CallToolRequest {
	var r mcp.CallToolRequest
	r.Params.Arguments = args
	return r
}

// decode unmarshals a tool result's JSON text payload into v.
func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool returned an error result: %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty tool result")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %T", res.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), v); err != nil {
		t.Fatalf("unmarshal result: %v (%s)", err, text.Text)
	}
}

func TestServerRegistersTools(t *testing.T) {
	st, _ := seed(t)
	_ = NewServer(st, "test") // must construct without panic
}

func TestListScans(t *testing.T) {
	st, ctx := seed(t)
	res, err := listScans(st)(ctx, call(nil))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	var scans []store.ScanMeta
	decode(t, res, &scans)
	if len(scans) != 1 || scans[0].ID != "s1" {
		t.Fatalf("expected scan s1, got %+v", scans)
	}
}

func TestScanSummary(t *testing.T) {
	st, ctx := seed(t)
	res, _ := scanSummary(st)(ctx, call(map[string]any{"scan": "latest"}))
	var out struct {
		Scan       string         `json:"scan"`
		Total      int            `json:"total_findings"`
		BySeverity map[string]int `json:"by_severity"`
		Paths      int            `json:"attack_paths"`
	}
	decode(t, res, &out)
	if out.Scan != "s1" || out.Total != 2 || out.BySeverity["critical"] != 1 || out.Paths != 1 {
		t.Fatalf("unexpected summary: %+v", out)
	}
}

func TestListFindingsWithSeverityFilter(t *testing.T) {
	st, ctx := seed(t)
	res, _ := listFindings(st)(ctx, call(map[string]any{"severity": "critical"}))
	var out struct {
		Findings        []findings.Finding `json:"findings"`
		UnknownServices []string           `json:"unknown_services"`
	}
	decode(t, res, &out)
	if len(out.Findings) != 1 || out.Findings[0].ID != "f-crit" {
		t.Fatalf("severity filter failed: %+v", out.Findings)
	}
	if len(out.UnknownServices) != 0 {
		t.Fatalf("no service filter was given; unknown_services should be empty, got %v", out.UnknownServices)
	}
}

func TestListFindingsUnknownServiceFlagged(t *testing.T) {
	st, ctx := seed(t)
	// "ec2" is not a service present in the seeded scan (iam, s3) — it must be
	// surfaced so an empty findings list is not read as "ec2 is clean".
	res, _ := listFindings(st)(ctx, call(map[string]any{"service": "ec2"}))
	var out struct {
		Findings        []findings.Finding `json:"findings"`
		UnknownServices []string           `json:"unknown_services"`
	}
	decode(t, res, &out)
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings for ec2, got %d", len(out.Findings))
	}
	if len(out.UnknownServices) != 1 || out.UnknownServices[0] != "ec2" {
		t.Fatalf("unknown service must be flagged, got %v", out.UnknownServices)
	}
}

func TestListFindingsInvalidSeverityIsError(t *testing.T) {
	st, ctx := seed(t)
	res, _ := listFindings(st)(ctx, call(map[string]any{"severity": "bogus"}))
	if !res.IsError {
		t.Fatal("an invalid severity must return an error result")
	}
}

func TestGetFinding(t *testing.T) {
	st, ctx := seed(t)
	res, _ := getFinding(st)(ctx, call(map[string]any{"id": "f-high"}))
	var f findings.Finding
	decode(t, res, &f)
	if f.ID != "f-high" || f.Remediation != "block it" {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestGetFindingMissingIDIsError(t *testing.T) {
	st, ctx := seed(t)
	res, _ := getFinding(st)(ctx, call(nil))
	if !res.IsError {
		t.Fatal("missing id must return an error result")
	}
	res2, _ := getFinding(st)(ctx, call(map[string]any{"id": "nope"}))
	if !res2.IsError {
		t.Fatal("unknown id must return an error result")
	}
}

func TestListAttackPaths(t *testing.T) {
	st, ctx := seed(t)
	res, _ := listAttackPaths(st)(ctx, call(map[string]any{"scan": "latest"}))
	var paths []graph.Path
	decode(t, res, &paths)
	if len(paths) != 1 || paths[0].ID != "p1" {
		t.Fatalf("unexpected paths: %+v", paths)
	}
}

func TestResolveScanUnknownIsError(t *testing.T) {
	st, ctx := seed(t)
	res, _ := scanSummary(st)(ctx, call(map[string]any{"scan": "no-such"}))
	if !res.IsError {
		t.Fatal("an unknown scan id must return an error result")
	}
}

func TestSeverityFilterValidation(t *testing.T) {
	// Severity parsing/validation now lives in the store package; confirm the
	// MCP list_findings path rejects an invalid severity as a tool error.
	st, ctx := seed(t)
	res, _ := listFindings(st)(ctx, call(map[string]any{"severity": "bogus"}))
	if !res.IsError {
		t.Fatal("an invalid severity must return an error result")
	}
}
