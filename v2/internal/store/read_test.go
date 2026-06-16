package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
)

// seedStore creates a store with two scans; the newer one (s2) holds three
// findings across severities and services, for the read/filter tests.
func seedStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "read.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	t0 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	if err := st.CreateScan(ctx, "s1", "aws", "111122223333", "arn:old", t0); err != nil {
		t.Fatalf("CreateScan s1: %v", err)
	}
	if err := st.SaveFindings(ctx, "s1", []findings.Finding{
		{ID: "old", CheckID: "c", Title: "old", Severity: findings.SeverityLow, Status: findings.StatusOpen, Provider: "aws", Service: "ec2", FirstSeen: t0, LastSeen: t0},
	}, t0); err != nil {
		t.Fatalf("SaveFindings s1: %v", err)
	}

	if err := st.CreateScan(ctx, "s2", "aws", "444455556666", "arn:new", t1); err != nil {
		t.Fatalf("CreateScan s2: %v", err)
	}
	if err := st.SaveFindings(ctx, "s2", []findings.Finding{
		{ID: "f-low", CheckID: "c1", Title: "low", Severity: findings.SeverityLow, Status: findings.StatusOpen, Provider: "aws", Service: "s3", Resource: findings.Resource{ID: "b1"}, FirstSeen: t1, LastSeen: t1},
		{ID: "f-crit", CheckID: "c2", Title: "crit", Severity: findings.SeverityCritical, Status: findings.StatusOpen, Provider: "aws", Service: "iam", Resource: findings.Resource{ID: "u1"}, FirstSeen: t1, LastSeen: t1},
		{ID: "f-high", CheckID: "c3", Title: "high", Severity: findings.SeverityHigh, Status: findings.StatusOpen, Provider: "aws", Service: "s3", Resource: findings.Resource{ID: "b2"}, FirstSeen: t1, LastSeen: t1},
	}, t1); err != nil {
		t.Fatalf("SaveFindings s2: %v", err)
	}
	return st, ctx
}

func TestLatestScanID(t *testing.T) {
	st, ctx := seedStore(t)
	id, err := st.LatestScanID(ctx)
	if err != nil {
		t.Fatalf("LatestScanID: %v", err)
	}
	if id != "s2" {
		t.Fatalf("expected latest s2, got %q", id)
	}
}

func TestLatestScanIDEmpty(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	if _, err := st.LatestScanID(ctx); err == nil {
		t.Fatal("expected error on empty database")
	}
}

func TestPreviousScanID(t *testing.T) {
	st, ctx := seedStore(t)

	prev, err := st.PreviousScanID(ctx, "s2")
	if err != nil {
		t.Fatalf("PreviousScanID(s2): %v", err)
	}
	if prev != "s1" {
		t.Fatalf("expected s1 before s2, got %q", prev)
	}

	// s1 is the earliest scan: no baseline, must surface ErrNoRows.
	if _, err := st.PreviousScanID(ctx, "s1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("PreviousScanID(s1) err = %v, want sql.ErrNoRows", err)
	}
}

func TestGetScan(t *testing.T) {
	st, ctx := seedStore(t)
	m, err := st.GetScan(ctx, "s2")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if m.Account != "444455556666" || m.Provider != "aws" || m.FindingCount != 3 {
		t.Fatalf("unexpected meta: %+v", m)
	}
	if m.FinishedAt.IsZero() {
		t.Fatal("expected finished_at to be set")
	}
}

func TestListScansNewestFirst(t *testing.T) {
	st, ctx := seedStore(t)
	scans, err := st.ListScans(ctx, 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(scans))
	}
	if scans[0].ID != "s2" || scans[1].ID != "s1" {
		t.Fatalf("expected newest-first [s2 s1], got [%s %s]", scans[0].ID, scans[1].ID)
	}
}

func TestLoadFindingsSortedBySeverity(t *testing.T) {
	st, ctx := seedStore(t)
	fs, err := st.LoadFindings(ctx, "s2", FindingFilter{})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(fs))
	}
	want := []findings.Severity{findings.SeverityCritical, findings.SeverityHigh, findings.SeverityLow}
	for i, sev := range want {
		if fs[i].Severity != sev {
			t.Fatalf("position %d: want %s, got %s", i, sev, fs[i].Severity)
		}
	}
}

func TestLoadFindingsFilterSeverity(t *testing.T) {
	st, ctx := seedStore(t)
	fs, err := st.LoadFindings(ctx, "s2", FindingFilter{
		Severities: []findings.Severity{findings.SeverityCritical, findings.SeverityHigh},
	})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	for _, f := range fs {
		if f.Severity == findings.SeverityLow {
			t.Fatalf("low-severity finding leaked through filter: %s", f.ID)
		}
	}
}

func TestLoadFindingsFilterService(t *testing.T) {
	st, ctx := seedStore(t)
	fs, err := st.LoadFindings(ctx, "s2", FindingFilter{Services: []string{"s3"}})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 s3 findings, got %d", len(fs))
	}
	for _, f := range fs {
		if f.Service != "s3" {
			t.Fatalf("non-s3 finding leaked: %s/%s", f.Service, f.ID)
		}
	}
}

func TestLoadFindingsScopedToScan(t *testing.T) {
	st, ctx := seedStore(t)
	fs, err := st.LoadFindings(ctx, "s1", FindingFilter{})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(fs) != 1 || fs[0].ID != "old" {
		t.Fatalf("expected only s1's finding, got %+v", fs)
	}
}

func TestDistinctServices(t *testing.T) {
	st, ctx := seedStore(t)
	svcs, err := st.DistinctServices(ctx, "s2")
	if err != nil {
		t.Fatalf("DistinctServices: %v", err)
	}
	// s2 has s3 (x2) and iam (x1) — distinct, sorted.
	if len(svcs) != 2 || svcs[0] != "iam" || svcs[1] != "s3" {
		t.Fatalf("expected [iam s3], got %v", svcs)
	}
}

func TestGetScanSurfacesCorruptTimestamp(t *testing.T) {
	st, ctx := seedStore(t)
	// Corrupt the stored started_at to a non-RFC3339 value behind the API.
	if _, err := st.db.ExecContext(ctx,
		`UPDATE scans SET started_at = 'not-a-timestamp' WHERE id = 's2'`); err != nil {
		t.Fatalf("corrupting row: %v", err)
	}
	if _, err := st.GetScan(ctx, "s2"); err == nil {
		t.Fatal("expected GetScan to surface the corrupt timestamp, got nil error")
	}
}

func TestCountAttackPathsZero(t *testing.T) {
	st, ctx := seedStore(t)
	n, err := st.CountAttackPaths(ctx, "s2")
	if err != nil {
		t.Fatalf("CountAttackPaths: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 attack paths, got %d", n)
	}
}

func sampleGraph() *graph.Graph {
	g := &graph.Graph{}
	g.Nodes = []graph.Node{
		{ID: graph.InternetNodeID, Kind: graph.NodeInternet, Label: "Internet"},
		{ID: "resource:aws_db_instance:db1", Kind: graph.NodeResource, Label: "db1", Type: "aws_db_instance"},
		{ID: "principal:user/alice", Kind: graph.NodePrincipal, Label: "alice", Type: "aws_iam_user"},
	}
	g.Edges = []graph.Edge{
		{Src: graph.InternetNodeID, Dst: "resource:aws_db_instance:db1", Kind: graph.EdgeExposedToInternet, PoC: "nc -vz ..."},
		{Src: "principal:user/alice", Dst: "principal:user/alice", Kind: graph.EdgeHoldsAdmin, PoC: "aws iam ..."},
	}
	g.Paths = []graph.Path{
		{ID: "p-low", Title: "low", Score: 30, Severity: findings.SeverityLow},
		{ID: "p-high", Title: "high", Score: 75, Severity: findings.SeverityHigh,
			Edges: []graph.Edge{{Src: graph.InternetNodeID, Dst: "resource:aws_db_instance:db1", Kind: graph.EdgeExposedToInternet}}},
	}
	return g
}

func TestSaveAndLoadGraph(t *testing.T) {
	st, ctx := seedStore(t)
	if err := st.SaveGraph(ctx, "s2", sampleGraph()); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	n, err := st.CountAttackPaths(ctx, "s2")
	if err != nil {
		t.Fatalf("CountAttackPaths: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 paths, got %d", n)
	}

	paths, err := st.LoadAttackPaths(ctx, "s2")
	if err != nil {
		t.Fatalf("LoadAttackPaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths loaded, got %d", len(paths))
	}
	// Highest score first.
	if paths[0].ID != "p-high" || paths[1].ID != "p-low" {
		t.Fatalf("expected score-desc order [p-high p-low], got [%s %s]", paths[0].ID, paths[1].ID)
	}
	// Lossless round-trip of nested edges.
	if len(paths[0].Edges) != 1 || paths[0].Edges[0].Kind != graph.EdgeExposedToInternet {
		t.Fatalf("path edges did not round-trip: %+v", paths[0].Edges)
	}
}

func TestSaveGraphIsIdempotent(t *testing.T) {
	st, ctx := seedStore(t)
	if err := st.SaveGraph(ctx, "s2", sampleGraph()); err != nil {
		t.Fatalf("first SaveGraph: %v", err)
	}
	// Re-saving the same scan must replace, not duplicate (edges have no PK).
	if err := st.SaveGraph(ctx, "s2", sampleGraph()); err != nil {
		t.Fatalf("second SaveGraph: %v", err)
	}
	n, err := st.CountAttackPaths(ctx, "s2")
	if err != nil {
		t.Fatalf("CountAttackPaths: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 paths after re-save (no duplication), got %d", n)
	}
}

func TestSaveGraphNilNoop(t *testing.T) {
	st, ctx := seedStore(t)
	if err := st.SaveGraph(ctx, "s2", nil); err != nil {
		t.Fatalf("SaveGraph(nil) should be a no-op, got %v", err)
	}
}

func TestParseSeverities(t *testing.T) {
	if s, err := ParseSeverities(""); err != nil || s != nil {
		t.Fatalf("empty = no filter, got %v / %v", s, err)
	}
	if s, err := ParseSeverities("critical,high"); err != nil || len(s) != 2 {
		t.Fatalf("valid list failed: %v / %v", s, err)
	}
	if _, err := ParseSeverities("bogus"); err == nil {
		t.Fatal("invalid severity must error")
	}
}

func TestSplitCSV(t *testing.T) {
	if SplitCSV("  ") != nil {
		t.Fatal("blank input is nil")
	}
	got := SplitCSV("iam, s3 ,,ec2")
	if len(got) != 3 || got[0] != "iam" || got[1] != "s3" || got[2] != "ec2" {
		t.Fatalf("unexpected split: %v", got)
	}
}
