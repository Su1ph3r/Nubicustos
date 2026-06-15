// Package export serializes findings into the formats downstream tools consume.
// The Cairn exporter emits the normalized, versioned findings JSON that the
// pentest-platform pipeline (Vinculum/Cepheus) ingests.
package export

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// CairnSchemaVersion is bumped on any breaking change to the export shape so
// Cairn ingestion can stay stable across nubicustos releases.
const CairnSchemaVersion = "1.0"

type cairnDoc struct {
	SchemaVersion string             `json:"schema_version"`
	Generator     string             `json:"generator"`
	GeneratedAt   string             `json:"generated_at"`
	Account       string             `json:"account,omitempty"`
	Provider      string             `json:"provider,omitempty"`
	Findings      []findings.Finding `json:"findings"`
}

// Cairn writes findings as the Cairn-compatible JSON document.
func Cairn(w io.Writer, provider, account string, fs []findings.Finding, generatedAt time.Time) error {
	doc := cairnDoc{
		SchemaVersion: CairnSchemaVersion,
		Generator:     "nubicustos",
		GeneratedAt:   generatedAt.UTC().Format(time.RFC3339),
		Account:       account,
		Provider:      provider,
		Findings:      fs,
	}
	if doc.Findings == nil {
		doc.Findings = []findings.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
