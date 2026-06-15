package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func TestCairnExport(t *testing.T) {
	var buf bytes.Buffer
	fs := []findings.Finding{
		{ID: "x", CheckID: "aws_s3_public_access", Title: "S3 bucket is publicly accessible", Severity: findings.SeverityHigh},
	}
	if err := Cairn(&buf, "aws", "123456789012", fs, time.Now()); err != nil {
		t.Fatalf("Cairn: %v", err)
	}

	var doc struct {
		SchemaVersion string             `json:"schema_version"`
		Generator     string             `json:"generator"`
		Findings      []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.SchemaVersion != CairnSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", doc.SchemaVersion, CairnSchemaVersion)
	}
	if doc.Generator != "nubicustos" {
		t.Fatalf("generator = %q", doc.Generator)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].CheckID != "aws_s3_public_access" {
		t.Fatalf("findings round-trip failed: %+v", doc.Findings)
	}
}

func TestCairnEmptyFindingsIsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := Cairn(&buf, "aws", "", nil, time.Now()); err != nil {
		t.Fatalf("Cairn: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"findings": []`)) {
		t.Fatalf("empty findings should serialize as [], got: %s", buf.String())
	}
}
