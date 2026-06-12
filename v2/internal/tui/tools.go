package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/Su1ph3r/nubicustos/internal/tui/theme"
)

// ToolStatus is one external tool's state, shown in the Tools view.
type ToolStatus struct {
	Name      string
	Category  string
	Available bool   // binary present on PATH
	HasRun    bool   // a prior run is recorded in the store
	LastRun   string // formatted timestamp of the last run ("" if never)
	Findings  int    // findings from the last run
}

// Actions is the side-effecting capability the Tools view needs: it lists the
// tools, runs them (persisting results), and reloads the view data. It is
// injected by the command layer so the TUI package never imports the store or
// exec directly and stays testable with a fake. A nil Actions puts the Tools
// view in a read-only "unavailable" state.
type Actions interface {
	// ListTools returns the tools with current availability and last-run info.
	ListTools() []ToolStatus
	// RunTool runs one tool by name (or every installed tool when name is ""),
	// against target, persists the findings, and returns a one-line summary.
	RunTool(name, target string) (summary string, err error)
	// LatestData reloads the view data for the most recent stored scan, so the
	// UI can refresh after a run created a new scan.
	LatestData() (Data, error)
}

// runDoneMsg is delivered when an async tool run finishes.
type runDoneMsg struct {
	summary string
	data    Data
	dataErr error
	err     error
}

func (m Model) selectedTool() (ToolStatus, bool) {
	if m.toolIdx < 0 || m.toolIdx >= len(m.tools) {
		return ToolStatus{}, false
	}
	return m.tools[m.toolIdx], true
}

// updateTools handles key input while the Tools view is focused and not editing
// the target field or running.
func (m Model) updateTools(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.toolIdx > 0 {
			m.toolIdx--
		}
	case "down", "j":
		if m.toolIdx < len(m.tools)-1 {
			m.toolIdx++
		}
	case "e":
		if m.actions != nil {
			m.editing = true
			m.target.Focus()
			return m, textinput.Blink
		}
	case "enter":
		t, ok := m.selectedTool()
		if !ok {
			return m, nil
		}
		if !t.Available {
			m.status = t.Name + " is not installed"
			return m, nil
		}
		return m.launchRun(t.Name)
	case "a":
		return m.launchRun("") // every installed tool
	}
	return m, nil
}

// updateTargetEdit routes keys to the target text field; enter/esc finish editing.
func (m Model) updateTargetEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.editing = false
		m.target.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.target, cmd = m.target.Update(msg)
	return m, cmd
}

// launchRun starts an async tool run and the spinner.
func (m Model) launchRun(name string) (tea.Model, tea.Cmd) {
	if m.actions == nil {
		m.status = "tool execution is unavailable in this session"
		return m, nil
	}
	m.running = true
	m.status = ""
	return m, tea.Batch(m.runCmd(name, m.target.Value()), m.spinner.Tick)
}

// runCmd runs the tool off the UI goroutine and reloads the latest scan data.
func (m Model) runCmd(name, target string) tea.Cmd {
	a := m.actions
	return func() tea.Msg {
		summary, err := a.RunTool(name, target)
		if err != nil {
			return runDoneMsg{err: err}
		}
		data, derr := a.LatestData()
		return runDoneMsg{summary: summary, data: data, dataErr: derr}
	}
}

func (m Model) toolsView() string {
	if m.actions == nil {
		return theme.Muted.Render("tool execution is unavailable in this session")
	}
	var b strings.Builder
	b.WriteString(m.target.View() + "\n\n")

	switch {
	case m.running:
		b.WriteString(m.spinner.View() + theme.Muted.Render(" running…") + "\n\n")
	case m.status != "":
		b.WriteString(theme.Value.Render(m.status) + "\n\n")
	}

	b.WriteString(theme.Label.Render("TOOLS") + "\n")
	if len(m.tools) == 0 {
		b.WriteString(theme.Muted.Render("  no tools registered") + "\n")
		return b.String()
	}
	for i, t := range m.tools {
		cursor := "  "
		if i == m.toolIdx {
			cursor = theme.Code.Render("▸ ")
		}
		avail := theme.Muted.Render("not installed")
		if t.Available {
			avail = theme.Value.Render("installed")
		}
		last := theme.Muted.Render("never run")
		if t.HasRun {
			last = theme.Muted.Render(fmt.Sprintf("last %s · %d findings", t.LastRun, t.Findings))
		}
		row := fmt.Sprintf("%-12s %-12s %-14s", t.Name, t.Category, "")
		b.WriteString(cursor + theme.Value.Render(row) + avail + "  " + last + "\n")
	}
	return b.String()
}
