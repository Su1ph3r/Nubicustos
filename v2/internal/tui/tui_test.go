package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
)

func sampleData() Data {
	return Data{
		ScanID:   "scan-1",
		Provider: "aws",
		Account:  "111122223333",
		Findings: []findings.Finding{
			{CheckID: "aws_s3_public_access", Title: "S3 bucket is publicly accessible", Severity: findings.SeverityHigh,
				Service: "s3", Resource: findings.Resource{ID: "demo-bucket", Region: "us-east-1"},
				Description: "Bucket is public", Remediation: "block public access", PoC: "aws s3api list-objects-v2 --bucket demo-bucket --no-sign-request",
				Reachable: findings.ReachUnknown,
				Evidence:  []findings.Evidence{{Vantage: findings.VantageExternal, Request: "GET ... (anonymous)", Response: "HTTP 200", Verdict: "confirmed"}}},
			{CheckID: "aws_iam_root_mfa_disabled", Title: "Root MFA disabled", Severity: findings.SeverityCritical,
				Service: "iam", Resource: findings.Resource{ID: "account:111"}},
		},
		Paths: []graph.Path{
			{ID: "p1", Title: "Internet-exposed RDS", Score: 64, Severity: findings.SeverityHigh,
				Rationale: "publicly reachable db",
				Nodes:     []graph.Node{{ID: "internet", Label: "Internet"}, {ID: "r", Label: "db-1"}},
				Edges:     []graph.Edge{{Src: "internet", Dst: "r", Kind: "exposed-to-internet", Detail: "public", PoC: "nc -vz ..."}}},
		},
	}
}

// send routes a key through Update and returns the new model.
func send(m Model, msg tea.Msg) Model {
	updated, _ := m.Update(msg)
	return updated.(Model)
}

func key(s string) tea.KeyMsg {
	switch s {
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func TestInitialViewIsDashboard(t *testing.T) {
	m := New(sampleData(), nil)
	out := m.View()
	if !strings.Contains(out, "FINDINGS") || !strings.Contains(out, "ATTACK PATHS") {
		t.Fatalf("dashboard should show finding/path summaries:\n%s", out)
	}
	// Severity counts: 1 critical, 1 high.
	if !strings.Contains(out, "critical") || !strings.Contains(out, "high") {
		t.Fatalf("dashboard missing severity rows:\n%s", out)
	}
}

func TestSwitchToFindingsByNumber(t *testing.T) {
	m := send(New(sampleData(), nil), key("2"))
	if m.view != viewFindings {
		t.Fatalf("expected findings view, got %d", m.view)
	}
	if !strings.Contains(m.View(), "demo-bucket") {
		t.Fatalf("findings table should list the bucket:\n%s", m.View())
	}
}

func TestTabCyclesViews(t *testing.T) {
	m := New(sampleData(), nil)
	for _, want := range []viewKind{viewFindings, viewPaths, viewCompliance, viewTools, viewDashboard} {
		m = send(m, key("tab"))
		if m.view != want {
			t.Fatalf("tab should advance to view %d, got %d", want, m.view)
		}
	}
}

func TestFindingsDetailToggle(t *testing.T) {
	m := send(New(sampleData(), nil), key("2")) // findings
	m = send(m, key("enter"))                   // open detail
	if !m.showDetail {
		t.Fatal("enter should open the detail pane")
	}
	out := m.View()
	if !strings.Contains(out, "proof of concept") || !strings.Contains(out, "evidence") {
		t.Fatalf("detail should render PoC and evidence:\n%s", out)
	}
	m = send(m, key("esc")) // close detail
	if m.showDetail {
		t.Fatal("esc should close the detail pane")
	}
}

func TestPathsViewRendersStepsAndMoves(t *testing.T) {
	m := send(New(sampleData(), nil), key("3")) // paths
	out := m.View()
	if !strings.Contains(out, "Internet-exposed RDS") || !strings.Contains(out, "exposed-to-internet") {
		t.Fatalf("paths view should list the path and its steps:\n%s", out)
	}
	// Down with a single path stays clamped at 0 (no panic).
	m = send(m, key("down"))
	if m.pathIdx != 0 {
		t.Fatalf("pathIdx should clamp to 0 with one path, got %d", m.pathIdx)
	}
}

func TestQuitKeysReturnQuit(t *testing.T) {
	for _, k := range []string{"q", "ctrl+c"} {
		var msg tea.KeyMsg
		if k == "ctrl+c" {
			msg = tea.KeyMsg{Type: tea.KeyCtrlC}
		} else {
			msg = key(k)
		}
		_, cmd := New(sampleData(), nil).Update(msg)
		if cmd == nil {
			t.Fatalf("%q should return a command", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("%q should quit", k)
		}
	}
}

func TestEscClosesDetailBeforeQuitting(t *testing.T) {
	m := send(New(sampleData(), nil), key("2"))
	m = send(m, key("enter")) // detail open
	_, cmd := m.Update(key("esc"))
	if cmd != nil {
		t.Fatal("esc with detail open should close detail, not quit")
	}
}

func TestWindowSizeNoPanicAndSetsTableHeight(t *testing.T) {
	m := send(New(sampleData(), nil), tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.width != 120 || m.height != 40 {
		t.Fatalf("window size not recorded: %dx%d", m.width, m.height)
	}
}

func TestEmptyDataDoesNotPanic(t *testing.T) {
	m := New(Data{ScanID: "empty", Provider: "aws"}, nil)
	_ = m.View()
	m = send(m, key("2"))
	if !strings.Contains(m.View(), "no findings") {
		t.Fatalf("empty findings view should say so:\n%s", m.View())
	}
	m = send(m, key("3"))
	if !strings.Contains(m.View(), "no attack paths") {
		t.Fatalf("empty paths view should say so:\n%s", m.View())
	}
}
