package compliance

import (
	"sort"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// ControlCoverage is one framework control and the Nubicustos checks that assess
// it, plus the count of open findings against those checks (0 = passing/covered).
type ControlCoverage struct {
	Control      Control  `json:"control"`
	CheckIDs     []string `json:"check_ids"`
	OpenFindings int      `json:"open_findings"`
	Status       string   `json:"status"` // "pass" | "fail"
}

// Report is a framework's control coverage built from the check catalog and an
// optional set of findings.
type Report struct {
	Framework string            `json:"framework"`
	Controls  []ControlCoverage `json:"controls"`
	Covered   int               `json:"covered_controls"`
	Failing   int               `json:"failing_controls"`
}

// Build produces the coverage report for framework from the registered check
// specs, overlaying findings to mark controls pass/fail. specs is the full check
// catalog (engine check specs); fs is the findings from a scan (may be empty for
// a pure coverage view).
func Build(framework string, specs []findings.CheckSpec, fs []findings.Finding) Report {
	// findings count per check id.
	findingsByCheck := map[string]int{}
	for _, f := range fs {
		findingsByCheck[f.CheckID]++
	}

	// Aggregate checks (and their finding counts) per control.
	type agg struct {
		control  Control
		checkIDs map[string]bool
		findings int
	}
	byControl := map[string]*agg{}
	for _, spec := range specs {
		cat := Classify(spec)
		ctrl, ok := ControlFor(cat, framework)
		if !ok {
			continue
		}
		a := byControl[ctrl.ID]
		if a == nil {
			a = &agg{control: ctrl, checkIDs: map[string]bool{}}
			byControl[ctrl.ID] = a
		}
		a.checkIDs[spec.ID] = true
		a.findings += findingsByCheck[spec.ID]
	}

	rep := Report{Framework: framework}
	for _, a := range byControl {
		ids := make([]string, 0, len(a.checkIDs))
		for id := range a.checkIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		status := "pass"
		if a.findings > 0 {
			status = "fail"
			rep.Failing++
		}
		rep.Covered++
		rep.Controls = append(rep.Controls, ControlCoverage{
			Control: a.control, CheckIDs: ids, OpenFindings: a.findings, Status: status,
		})
	}
	sort.Slice(rep.Controls, func(i, j int) bool { return rep.Controls[i].Control.ID < rep.Controls[j].Control.ID })
	return rep
}

// ValidFramework reports whether name is a supported framework id.
func ValidFramework(name string) bool {
	switch name {
	case FrameworkSOC2, FrameworkPCI, FrameworkNIST:
		return true
	default:
		return false
	}
}
