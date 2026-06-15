package export

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// SARIF emits a SARIF 2.1.0 document so findings can be ingested by code-scanning
// dashboards (GitHub Advanced Security, Azure DevOps, etc.). One rule per distinct
// check, one result per finding.
func SARIF(w io.Writer, fs []findings.Finding, generatedAt time.Time) error {
	rules, ruleIndex := sarifRules(fs)

	results := make([]sarifResult, 0, len(fs))
	for _, f := range fs {
		results = append(results, sarifResult{
			RuleID:    f.CheckID,
			RuleIndex: ruleIndex[f.CheckID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: sarifResultText(f)},
			Locations: sarifLocations(f),
			Properties: map[string]any{
				"severity":  string(f.Severity),
				"service":   f.Service,
				"reachable": string(f.Reachable),
			},
		})
	}

	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "nubicustos",
				InformationURI: "https://github.com/Su1ph3r/nubicustos",
				Version:        sarifGeneratorVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	_ = generatedAt // SARIF carries timestamps per-invocation; omitted to keep output deterministic.

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifGeneratorVersion is reported as the SARIF tool driver version.
const sarifGeneratorVersion = "2.0.0"

// sarifRules builds the deduplicated rule set and a checkID→index map.
func sarifRules(fs []findings.Finding) ([]sarifRule, map[string]int) {
	index := map[string]int{}
	var rules []sarifRule
	for _, f := range fs {
		if _, seen := index[f.CheckID]; seen {
			continue
		}
		index[f.CheckID] = len(rules)
		rule := sarifRule{
			ID:               f.CheckID,
			Name:             f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			Properties: map[string]any{
				// GitHub renders this 0-10 band as the severity chip.
				"security-severity": securitySeverity(f.Severity),
				"tags":              sarifTags(f),
			},
		}
		if f.Rationale != "" {
			rule.FullDescription = &sarifMessage{Text: f.Rationale}
		}
		if f.Remediation != "" {
			rule.Help = &sarifMessage{Text: f.Remediation}
		}
		if len(f.References) > 0 {
			rule.HelpURI = f.References[0]
		}
		rules = append(rules, rule)
	}
	return rules, index
}

func sarifTags(f findings.Finding) []string {
	tags := []string{"security", f.Provider}
	if f.Service != "" {
		tags = append(tags, f.Service)
	}
	for _, c := range f.Compliance {
		tags = append(tags, c.Framework+" "+c.Control)
	}
	return tags
}

// sarifLevel maps our severity to SARIF's result level vocabulary.
func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps to the 0.0-10.0 numeric band GitHub uses to render the
// severity chip on SARIF results.
func securitySeverity(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return "9.5"
	case findings.SeverityHigh:
		return "8.0"
	case findings.SeverityMedium:
		return "5.5"
	case findings.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func sarifResultText(f findings.Finding) string {
	if f.Description != "" {
		return f.Description
	}
	return f.Title
}

// sarifLocations represents the affected cloud resource as a logical location,
// since cloud findings have no source file/line to anchor to.
func sarifLocations(f findings.Finding) []sarifLocation {
	name := f.Resource.ARN
	if name == "" {
		name = f.Resource.ID
	}
	if name == "" && len(f.Affected) > 0 {
		name = fmt.Sprintf("%d affected resources", len(f.Affected))
	}
	if name == "" {
		return nil
	}
	return []sarifLocation{{
		LogicalLocations: []sarifLogicalLocation{{
			Name:               name,
			FullyQualifiedName: name,
			Kind:               "resource",
		}},
	}}
}

// SARIF 2.1.0 minimal type model.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  *sarifMessage  `json:"fullDescription,omitempty"`
	Help             *sarifMessage  `json:"help,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
