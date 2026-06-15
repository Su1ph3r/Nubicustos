// Package theme holds the lipgloss styles for the terminal UI. The palette is a
// security-ops aesthetic — dark background, severity-coded accents — chosen to
// fit an operator/pentest workflow rather than a generic dashboard look.
package theme

import "github.com/charmbracelet/lipgloss"

// Severity accent colors.
var (
	colorCritical = lipgloss.Color("#ff5f5f")
	colorHigh     = lipgloss.Color("#ff875f")
	colorMedium   = lipgloss.Color("#ffd75f")
	colorLow      = lipgloss.Color("#5fafff")
	colorInfo     = lipgloss.Color("#8a8a8a")
	colorMuted    = lipgloss.Color("#6c6c6c")
	colorAccent   = lipgloss.Color("#5fd7af")
	colorText     = lipgloss.Color("#dadada")
)

// Shared styles.
var (
	Title = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	Muted = lipgloss.NewStyle().Foreground(colorMuted)
	Label = lipgloss.NewStyle().Foreground(colorMuted).Bold(true)
	Value = lipgloss.NewStyle().Foreground(colorText)

	TabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0d1117")).Background(colorAccent).Padding(0, 1)
	TabInactive = lipgloss.NewStyle().Foreground(colorMuted).Padding(0, 1)

	Detail = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorMuted).Padding(0, 1)
	Code   = lipgloss.NewStyle().Foreground(colorAccent)
)

// Severity returns the accent style for a severity string (critical|high|...).
func Severity(sev string) lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(severityColor(sev))
}

func severityColor(sev string) lipgloss.Color {
	switch sev {
	case "critical":
		return colorCritical
	case "high":
		return colorHigh
	case "medium":
		return colorMedium
	case "low":
		return colorLow
	default:
		return colorInfo
	}
}
