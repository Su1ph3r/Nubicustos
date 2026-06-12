package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

// fakeActions records calls and returns canned results, so the Tools view is
// testable without a store or real subprocesses.
type fakeActions struct {
	tools     []ToolStatus
	runName   string
	runTarget string
	runErr    error
	reload    Data
	reloadErr error
}

func (f *fakeActions) ListTools() []ToolStatus { return f.tools }
func (f *fakeActions) RunTool(name, target string) (string, error) {
	f.runName, f.runTarget = name, target
	if f.runErr != nil {
		return "", f.runErr
	}
	return "ran " + name, nil
}
func (f *fakeActions) LatestData() (Data, error) { return f.reload, f.reloadErr }

func toolsModel(a Actions) Model {
	m := New(sampleData(), a)
	return send(m, key("4")) // switch to Tools view
}

func TestToolsViewListsToolsWithStatus(t *testing.T) {
	a := &fakeActions{tools: []ToolStatus{
		{Name: "trivy", Category: "vuln", Available: true, HasRun: true, LastRun: "2026-06-12 09:00", Findings: 3},
		{Name: "grype", Category: "vuln", Available: false},
	}}
	out := toolsModel(a).View()
	if !strings.Contains(out, "trivy") || !strings.Contains(out, "installed") {
		t.Fatalf("tools view should show an installed tool:\n%s", out)
	}
	if !strings.Contains(out, "not installed") {
		t.Fatalf("tools view should show an uninstalled tool:\n%s", out)
	}
	if !strings.Contains(out, "3 findings") {
		t.Fatalf("tools view should show last-run finding count:\n%s", out)
	}
}

func TestToolsViewNilActionsIsReadOnly(t *testing.T) {
	out := send(New(sampleData(), nil), key("4")).View()
	if !strings.Contains(out, "unavailable") {
		t.Fatalf("a nil Actions should render the Tools view as unavailable:\n%s", out)
	}
}

func TestRunSelectedToolLaunchesAndCompletes(t *testing.T) {
	a := &fakeActions{
		tools:  []ToolStatus{{Name: "trivy", Category: "vuln", Available: true}},
		reload: Data{ScanID: "scan-new", Provider: "plugin:trivy"},
	}
	m := toolsModel(a)
	m2, cmd := m.Update(key("enter"))
	m = m2.(Model)
	if !m.running {
		t.Fatal("enter on an available tool should start a run")
	}
	if cmd == nil {
		t.Fatal("launching a run should return a command (run + spinner)")
	}
	// Execute the run command to confirm it calls RunTool and emits completion.
	msg := m.runCmd("trivy", m.target.Value())()
	done, ok := msg.(runDoneMsg)
	if !ok {
		t.Fatalf("run command should emit runDoneMsg, got %T", msg)
	}
	if a.runName != "trivy" {
		t.Fatalf("expected trivy to be run, got %q", a.runName)
	}
	m = send(m, done)
	if m.running {
		t.Fatal("run completion should clear the running flag")
	}
	if m.data.ScanID != "scan-new" {
		t.Fatalf("completion should refresh data to the new scan, got %q", m.data.ScanID)
	}
	if !strings.Contains(m.status, "ran trivy") {
		t.Fatalf("status should show the run summary, got %q", m.status)
	}
}

func TestRunSelectedToolNotInstalledIsRefused(t *testing.T) {
	a := &fakeActions{tools: []ToolStatus{{Name: "grype", Category: "vuln", Available: false}}}
	m := toolsModel(a)
	m = send(m, key("enter"))
	if m.running {
		t.Fatal("an uninstalled tool must not start a run")
	}
	if a.runName != "" {
		t.Fatal("RunTool must not be called for an uninstalled tool")
	}
	if !strings.Contains(m.status, "not installed") {
		t.Fatalf("status should explain the tool is not installed, got %q", m.status)
	}
}

func TestRunAllUsesEmptyName(t *testing.T) {
	a := &fakeActions{tools: []ToolStatus{{Name: "trivy", Available: false}}}
	m := toolsModel(a)
	m2, _ := m.Update(key("a"))
	m = m2.(Model)
	if !m.running {
		t.Fatal("'a' should launch a run-all")
	}
	// Execute the run command: run-all must pass an empty tool name.
	if _, ok := m.runCmd("", m.target.Value())().(runDoneMsg); !ok {
		t.Fatal("run command should emit runDoneMsg")
	}
	if a.runName != "" {
		t.Fatalf("run-all must pass an empty tool name, got %q", a.runName)
	}
}

func TestRunFailureSurfacedInStatus(t *testing.T) {
	a := &fakeActions{tools: []ToolStatus{{Name: "trivy", Available: true}}, runErr: errors.New("boom")}
	m := toolsModel(a)
	m2, _ := m.Update(key("enter"))
	m = m2.(Model)
	// Drive the async cmd manually to get the runDoneMsg with the error.
	m = send(m, runDoneMsg{err: errors.New("boom")})
	if m.running {
		t.Fatal("a failed run should clear the running flag")
	}
	if !strings.Contains(m.status, "run failed") || !strings.Contains(m.status, "boom") {
		t.Fatalf("status should surface the failure, got %q", m.status)
	}
}

func TestTargetEditingCapturesInput(t *testing.T) {
	a := &fakeActions{tools: []ToolStatus{{Name: "trivy", Available: true}}}
	m := toolsModel(a)
	m = send(m, key("e")) // enter edit mode
	if !m.editing {
		t.Fatal("'e' should enter target-edit mode")
	}
	// Type into the target field; navigation keys must not switch views here.
	for _, r := range "x" {
		m = send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	m = send(m, key("esc")) // finish editing
	if m.editing {
		t.Fatal("esc should leave edit mode")
	}
	if !strings.Contains(m.target.Value(), "x") {
		t.Fatalf("typed input should be captured in the target, got %q", m.target.Value())
	}
}

func TestSpinnerTickIgnoredWhenNotRunning(t *testing.T) {
	m := toolsModel(&fakeActions{})
	_, cmd := m.Update(spinner.TickMsg{})
	if cmd != nil {
		t.Fatal("a spinner tick while not running must not reschedule")
	}
}
