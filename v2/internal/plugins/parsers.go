package plugins

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// finding builds a normalized Finding from a plugin result. The provider is the
// tool name (e.g. "trivy") so plugin findings are attributable and filterable
// alongside native ones.
func (p pluginFinding) toFinding(m Manifest, now time.Time) findings.Finding {
	return findings.Finding{
		ID:          m.Name + ":" + p.checkID + "::" + p.resource,
		CheckID:     m.Name + ":" + p.checkID,
		Title:       p.title,
		Severity:    normalizeSeverity(p.severity),
		Status:      findings.StatusOpen,
		Provider:    m.Name,
		Service:     m.Service,
		Resource:    findings.Resource{ID: p.resource, Name: p.resource, Type: p.resType, Provider: m.Name},
		Description: p.description,
		Remediation: p.remediation,
		Reachable:   findings.ReachUnknown,
		FirstSeen:   now,
		LastSeen:    now,
	}
}

// pluginFinding is the small intermediate each parser populates before mapping
// to the shared Finding model.
type pluginFinding struct {
	checkID     string
	title       string
	severity    string
	resource    string
	resType     string
	description string
	remediation string
}

func build(m Manifest, items []pluginFinding) []findings.Finding {
	now := time.Now().UTC()
	out := make([]findings.Finding, 0, len(items))
	for _, it := range items {
		out = append(out, it.toFinding(m, now))
	}
	return out
}

// --- trivy ------------------------------------------------------------------

func parseTrivy(m Manifest, raw []byte) ([]findings.Finding, error) {
	var doc struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				Description      string `json:"Description"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
				Resolution  string `json:"Resolution"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("trivy json: %w", err)
	}
	var items []pluginFinding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			items = append(items, pluginFinding{
				checkID: v.VulnerabilityID, title: v.Title, severity: v.Severity,
				resource: r.Target, resType: v.PkgName,
				description: fmt.Sprintf("%s in %s@%s (fixed: %s). %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion, v.Description),
				remediation: upgradeHint(v.PkgName, v.FixedVersion),
			})
		}
		for _, mc := range r.Misconfigurations {
			items = append(items, pluginFinding{
				checkID: mc.ID, title: mc.Title, severity: mc.Severity,
				resource: r.Target, resType: "misconfiguration",
				description: mc.Description, remediation: mc.Resolution,
			})
		}
	}
	return build(m, items), nil
}

func upgradeHint(pkg, fixed string) string {
	if fixed == "" {
		return "no fixed version available yet; monitor the advisory"
	}
	return fmt.Sprintf("upgrade %s to %s or later", pkg, fixed)
}

// --- grype ------------------------------------------------------------------

func parseGrype(m Manifest, raw []byte) ([]findings.Finding, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("grype json: %w", err)
	}
	var items []pluginFinding
	for _, mt := range doc.Matches {
		items = append(items, pluginFinding{
			checkID: mt.Vulnerability.ID, title: mt.Vulnerability.ID, severity: mt.Vulnerability.Severity,
			resource: fmt.Sprintf("%s@%s", mt.Artifact.Name, mt.Artifact.Version), resType: "package",
			description: mt.Vulnerability.Description,
			remediation: "upgrade the affected package to a fixed version",
		})
	}
	return build(m, items), nil
}

// --- checkov ----------------------------------------------------------------

func parseCheckov(m Manifest, raw []byte) ([]findings.Finding, error) {
	// checkov emits either a single object or, with multiple frameworks, an array.
	var single checkovDoc
	if err := json.Unmarshal(raw, &single); err == nil && single.Results.FailedChecks != nil {
		return build(m, checkovItems([]checkovDoc{single})), nil
	}
	var multi []checkovDoc
	if err := json.Unmarshal(raw, &multi); err != nil {
		return nil, fmt.Errorf("checkov json: %w", err)
	}
	return build(m, checkovItems(multi)), nil
}

type checkovDoc struct {
	Results struct {
		FailedChecks []struct {
			CheckID   string `json:"check_id"`
			CheckName string `json:"check_name"`
			Severity  string `json:"severity"`
			FilePath  string `json:"file_path"`
			Resource  string `json:"resource"`
			Guideline string `json:"guideline"`
		} `json:"failed_checks"`
	} `json:"results"`
}

func checkovItems(docs []checkovDoc) []pluginFinding {
	var items []pluginFinding
	for _, d := range docs {
		for _, c := range d.Results.FailedChecks {
			items = append(items, pluginFinding{
				checkID: c.CheckID, title: c.CheckName, severity: c.Severity,
				resource: c.Resource, resType: "iac_resource",
				description: fmt.Sprintf("%s failed for %s in %s", c.CheckID, c.Resource, c.FilePath),
				remediation: c.Guideline,
			})
		}
	}
	return items
}

// --- terrascan --------------------------------------------------------------

func parseTerrascan(m Manifest, raw []byte) ([]findings.Finding, error) {
	var doc struct {
		Results struct {
			Violations []struct {
				RuleName     string `json:"rule_name"`
				Description  string `json:"description"`
				Severity     string `json:"severity"`
				Category     string `json:"category"`
				ResourceName string `json:"resource_name"`
				ResourceType string `json:"resource_type"`
				File         string `json:"file"`
			} `json:"violations"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("terrascan json: %w", err)
	}
	var items []pluginFinding
	for _, v := range doc.Results.Violations {
		items = append(items, pluginFinding{
			checkID: v.RuleName, title: v.Description, severity: v.Severity,
			resource: v.ResourceName, resType: v.ResourceType,
			description: fmt.Sprintf("%s on %s (%s) in %s", v.Description, v.ResourceName, v.ResourceType, v.File),
			// terrascan violations carry no per-finding remediation field; point
			// the operator at the offending rule so the finding is still actionable.
			remediation: terrascanRemediation(v.RuleName, v.Category, v.ResourceType),
		})
	}
	return build(m, items), nil
}

func terrascanRemediation(rule, category, resType string) string {
	hint := fmt.Sprintf("Resolve terrascan rule %s on %s", rule, resType)
	if category != "" {
		hint += " (category: " + category + ")"
	}
	return hint + "; see the terrascan policy reference for the fix."
}

// --- kube-bench -------------------------------------------------------------

func parseKubeBench(m Manifest, raw []byte) ([]findings.Finding, error) {
	var doc struct {
		Controls []struct {
			Tests []struct {
				Results []struct {
					TestNumber  string `json:"test_number"`
					TestDesc    string `json:"test_desc"`
					Status      string `json:"status"` // PASS | FAIL | WARN
					Remediation string `json:"remediation"`
				} `json:"results"`
			} `json:"tests"`
		} `json:"Controls"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kube-bench json: %w", err)
	}
	var items []pluginFinding
	for _, ctrl := range doc.Controls {
		for _, test := range ctrl.Tests {
			for _, r := range test.Results {
				if r.Status == "PASS" {
					continue // only report FAIL/WARN
				}
				sev := "medium"
				if r.Status == "FAIL" {
					sev = "high"
				} else if r.Status == "WARN" {
					sev = "low"
				}
				items = append(items, pluginFinding{
					checkID: r.TestNumber, title: r.TestDesc, severity: sev,
					resource: r.TestNumber, resType: "cis_control",
					description: fmt.Sprintf("CIS %s [%s]: %s", r.TestNumber, r.Status, r.TestDesc),
					remediation: r.Remediation,
				})
			}
		}
	}
	return build(m, items), nil
}
