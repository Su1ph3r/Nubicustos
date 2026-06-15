package tui

import (
	"fmt"
	"strings"

	"github.com/Su1ph3r/nubicustos/internal/compliance"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/tui/theme"
)

// complianceView renders the scan's coverage against SOC2, PCI-DSS, and NIST:
// per framework, how many controls the native checks cover and which are failing
// (have open findings in this scan), with the failing controls listed.
func (m Model) complianceView() string {
	specs := checkSpecs()
	if len(specs) == 0 {
		return theme.Muted.Render("compliance mapping unavailable (no checks registered)")
	}

	var b strings.Builder
	for _, fw := range []struct{ id, name string }{
		{compliance.FrameworkSOC2, "SOC 2"},
		{compliance.FrameworkPCI, "PCI-DSS v4.0"},
		{compliance.FrameworkNIST, "NIST 800-53"},
	} {
		rep := compliance.Build(fw.id, specs, m.data.Findings)
		header := fmt.Sprintf("%s — %d control(s) covered · %d failing", fw.name, rep.Covered, rep.Failing)
		b.WriteString(theme.Label.Render(header) + "\n")
		for _, c := range rep.Controls {
			line := fmt.Sprintf("  %-7s %s  (%d check(s))", c.Control.ID, c.Control.Title, len(c.CheckIDs))
			if c.Status == "fail" {
				b.WriteString(theme.Severity("critical").Render(line+fmt.Sprintf("  FAIL: %d finding(s)", c.OpenFindings)) + "\n")
			} else {
				b.WriteString(theme.Muted.Render(line) + "\n")
			}
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// checkSpecs returns the registered check catalog's specs (populated by the
// check packages' init registration in the running binary).
func checkSpecs() []findings.CheckSpec {
	cks := engine.Checks()
	specs := make([]findings.CheckSpec, 0, len(cks))
	for _, c := range cks {
		specs = append(specs, c.Spec())
	}
	return specs
}
