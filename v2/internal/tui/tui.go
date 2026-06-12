// Package tui is the terminal UI (plan §3.5): a bubbletea app that browses a
// completed scan — a dashboard, a filterable findings table with a detail pane,
// and the attack-path list with step-by-step chained PoCs. It reads a scan's
// data up front (no live cloud calls), so the model is a pure function of its
// inputs and is testable without a TTY.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/tui/theme"
)

// Data is the scan content the UI renders. It is loaded once before the program
// starts; the model never touches the store or the cloud.
type Data struct {
	ScanID   string
	Provider string
	Account  string
	Findings []findings.Finding
	Paths    []graph.Path
}

type viewKind int

const (
	viewDashboard viewKind = iota
	viewFindings
	viewPaths
	viewTools
)

const viewCount = 4

var viewNames = []string{"Dashboard", "Findings", "Attack Paths", "Tools"}

// Model is the root bubbletea model.
type Model struct {
	data       Data
	view       viewKind
	width      int
	height     int
	table      table.Model
	showDetail bool
	pathIdx    int

	// Tools view (optional, side-effecting via actions).
	actions Actions
	tools   []ToolStatus
	toolIdx int
	target  textinput.Model
	editing bool
	running bool
	spinner spinner.Model
	status  string
}

// New builds the model from loaded scan data. actions enables the Tools view to
// run external tools; pass nil for a purely read-only viewer.
func New(d Data, actions Actions) Model {
	ti := textinput.New()
	ti.Prompt = "target ▸ "
	ti.Placeholder = "path / image / directory"
	ti.SetValue(".")

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	m := Model{
		data:    d,
		table:   newFindingsTable(d.Findings),
		actions: actions,
		target:  ti,
		spinner: sp,
	}
	if actions != nil {
		m.tools = actions.ListTools()
	}
	return m
}

func newFindingsTable(fs []findings.Finding) table.Model {
	cols := []table.Column{
		{Title: "SEVERITY", Width: 9},
		{Title: "SERVICE", Width: 10},
		{Title: "CHECK", Width: 34},
		{Title: "REGION", Width: 12},
		{Title: "RESOURCE", Width: 28},
	}
	rows := make([]table.Row, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, table.Row{
			strings.ToUpper(string(f.Severity)),
			f.Service,
			f.CheckID,
			regionOrDash(f),
			resourceLabel(f),
		})
	}
	return table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(12),
	)
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.table.SetHeight(maxInt(5, msg.Height-10))
		return m, nil

	case spinner.TickMsg:
		if !m.running {
			return m, nil // stop ticking once the run finished
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case runDoneMsg:
		m.running = false
		if msg.err != nil {
			m.status = "run failed: " + msg.err.Error()
			return m, nil
		}
		m.status = msg.summary
		if msg.dataErr != nil {
			m.status += "  (reload failed: " + msg.dataErr.Error() + ")"
		} else {
			m.data = msg.data
			m.table = newFindingsTable(msg.data.Findings)
		}
		if m.actions != nil {
			m.tools = m.actions.ListTools() // refresh last-run/finding counts
		}
		return m, nil

	case tea.KeyMsg:
		// While a tool runs, swallow input except an explicit quit.
		if m.running {
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			return m, nil
		}
		// While editing the target field, keys go to the input (enter/esc exit).
		if m.editing {
			return m.updateTargetEdit(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c", "esc":
			if msg.String() == "esc" && m.showDetail {
				m.showDetail = false
				return m, nil
			}
			return m, tea.Quit
		case "1":
			m.view, m.showDetail = viewDashboard, false
			return m, nil
		case "2":
			m.view, m.showDetail = viewFindings, false
			return m, nil
		case "3":
			m.view, m.showDetail = viewPaths, false
			return m, nil
		case "4":
			m.view, m.showDetail = viewTools, false
			return m, nil
		case "tab":
			m.view = (m.view + 1) % viewCount
			m.showDetail = false
			return m, nil
		case "shift+tab":
			m.view = (m.view + viewCount - 1) % viewCount
			m.showDetail = false
			return m, nil
		}

		switch m.view {
		case viewFindings:
			return m.updateFindings(msg)
		case viewPaths:
			return m.updatePaths(msg)
		case viewTools:
			return m.updateTools(msg)
		}
	}
	return m, nil
}

func (m Model) updateFindings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "enter" && len(m.data.Findings) > 0 {
		m.showDetail = !m.showDetail
		return m, nil
	}
	if m.showDetail {
		return m, nil // detail is static; navigation resumes on esc/enter
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m Model) updatePaths(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.pathIdx > 0 {
			m.pathIdx--
		}
	case "down", "j":
		if m.pathIdx < len(m.data.Paths)-1 {
			m.pathIdx++
		}
	}
	return m, nil
}

// View implements tea.Model.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n\n")
	switch m.view {
	case viewDashboard:
		b.WriteString(m.dashboard())
	case viewFindings:
		b.WriteString(m.findingsView())
	case viewPaths:
		b.WriteString(m.pathsView())
	case viewTools:
		b.WriteString(m.toolsView())
	}
	b.WriteString("\n\n")
	b.WriteString(m.footer())
	return b.String()
}

func (m Model) header() string {
	tabs := make([]string, len(viewNames))
	for i, name := range viewNames {
		if viewKind(i) == m.view {
			tabs[i] = theme.TabActive.Render(name)
		} else {
			tabs[i] = theme.TabInactive.Render(name)
		}
	}
	title := theme.Title.Render("nubicustos")
	meta := theme.Muted.Render(fmt.Sprintf("  %s · %s · %s", m.data.Provider, m.data.Account, m.data.ScanID))
	return title + meta + "\n" + lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
}

func (m Model) footer() string {
	if m.editing {
		return theme.Muted.Render("type a target · enter/esc: done")
	}
	keys := "1/2/3/4 or tab: switch · q: quit"
	switch m.view {
	case viewFindings:
		keys = "↑/↓: move · enter: detail · esc: back · " + keys
	case viewPaths:
		keys = "↑/↓: select path · " + keys
	case viewTools:
		keys = "↑/↓: select · enter: run · a: run all · e: edit target · " + keys
	}
	return theme.Muted.Render(keys)
}

func (m Model) dashboard() string {
	counts := map[findings.Severity]int{}
	for _, f := range m.data.Findings {
		counts[f.Severity]++
	}
	var b strings.Builder
	b.WriteString(theme.Label.Render("FINDINGS") + "\n")
	for _, sev := range []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium,
		findings.SeverityLow, findings.SeverityInfo,
	} {
		line := fmt.Sprintf("  %-9s %d", string(sev), counts[sev])
		b.WriteString(theme.Severity(string(sev)).Render(line) + "\n")
	}
	b.WriteString(theme.Value.Render(fmt.Sprintf("  %-9s %d", "total", len(m.data.Findings))) + "\n\n")

	b.WriteString(theme.Label.Render("ATTACK PATHS") + "\n")
	if len(m.data.Paths) == 0 {
		b.WriteString(theme.Muted.Render("  none") + "\n")
		return b.String()
	}
	top := m.data.Paths
	if len(top) > 5 {
		top = top[:5]
	}
	for _, p := range top {
		marker := theme.Severity(string(p.Severity)).Render(fmt.Sprintf("  [%3d]", p.Score))
		b.WriteString(marker + " " + theme.Value.Render(p.Title) + "\n")
	}
	return b.String()
}

func (m Model) findingsView() string {
	if len(m.data.Findings) == 0 {
		return theme.Muted.Render("no findings in this scan")
	}
	if m.showDetail {
		return m.detail(m.data.Findings[clamp(m.table.Cursor(), len(m.data.Findings))])
	}
	return m.table.View()
}

func (m Model) detail(f findings.Finding) string {
	var b strings.Builder
	b.WriteString(theme.Severity(string(f.Severity)).Render(strings.ToUpper(string(f.Severity))) + "  ")
	b.WriteString(theme.Title.Render(f.Title) + "\n\n")
	row := func(label, val string) {
		if val == "" {
			return
		}
		b.WriteString(theme.Label.Render(label) + "\n  " + theme.Value.Render(val) + "\n")
	}
	row("resource", resourceLabel(f))
	row("description", f.Description)
	row("impact", f.Impact)
	row("remediation", f.Remediation)
	if f.PoC != "" {
		b.WriteString(theme.Label.Render("proof of concept") + "\n  " + theme.Code.Render(f.PoC) + "\n")
	}
	if string(f.Reachable) != "" {
		row("reachable", string(f.Reachable))
	}
	for _, e := range f.Evidence {
		b.WriteString(theme.Label.Render("evidence ("+string(e.Vantage)+", "+e.Verdict+")") + "\n  " +
			theme.Value.Render(e.Request) + "\n  " + theme.Muted.Render(e.Response) + "\n")
	}
	return theme.Detail.Render(b.String())
}

func (m Model) pathsView() string {
	if len(m.data.Paths) == 0 {
		return theme.Muted.Render("no attack paths in this scan")
	}
	idx := clamp(m.pathIdx, len(m.data.Paths))
	var list strings.Builder
	for i, p := range m.data.Paths {
		cursor := "  "
		if i == idx {
			cursor = theme.Code.Render("▸ ")
		}
		score := theme.Severity(string(p.Severity)).Render(fmt.Sprintf("[%3d]", p.Score))
		list.WriteString(cursor + score + " " + theme.Value.Render(p.Title) + "\n")
	}

	p := m.data.Paths[idx]
	var steps strings.Builder
	steps.WriteString("\n" + theme.Label.Render("PATH") + "\n")
	if p.Rationale != "" {
		steps.WriteString(theme.Muted.Render(p.Rationale) + "\n\n")
	}
	for i, e := range p.Edges {
		src := nodeLabel(p.Nodes, e.Src)
		dst := nodeLabel(p.Nodes, e.Dst)
		hop := fmt.Sprintf("%d. %s → %s", i+1, src, dst)
		if e.Src == e.Dst {
			hop = fmt.Sprintf("%d. %s", i+1, src)
		}
		steps.WriteString(theme.Value.Render(hop) + "  " + theme.Muted.Render("["+string(e.Kind)+"]") + "\n")
		if e.Detail != "" {
			steps.WriteString("   " + theme.Muted.Render(e.Detail) + "\n")
		}
		if e.PoC != "" {
			steps.WriteString("   " + theme.Code.Render(e.PoC) + "\n")
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, list.String(), theme.Detail.Render(steps.String()))
}

// --- helpers ---------------------------------------------------------------

func regionOrDash(f findings.Finding) string {
	if f.Resource.Region == "" {
		return "-"
	}
	return f.Resource.Region
}

func resourceLabel(f findings.Finding) string {
	if f.Resource.ID != "" {
		return f.Resource.ID
	}
	if n := len(f.Affected); n > 0 {
		return fmt.Sprintf("%d affected", n)
	}
	return "-"
}

func nodeLabel(nodes []graph.Node, id string) string {
	for _, n := range nodes {
		if n.ID == id && n.Label != "" {
			return n.Label
		}
	}
	return id
}

func clamp(i, n int) int {
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
