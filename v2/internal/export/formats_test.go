package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func sampleFindings() []findings.Finding {
	return []findings.Finding{
		{
			ID: "f1", CheckID: "aws_s3_public_access", Title: "S3 bucket is publicly accessible",
			Severity: findings.SeverityHigh, Status: findings.StatusOpen, Provider: "aws", Service: "s3",
			Resource:    findings.Resource{ID: "my-bucket", Type: "aws_s3_bucket", ARN: "arn:aws:s3:::my-bucket", Region: "us-east-1"},
			Description: "Bucket is public", Rationale: "anon read", Impact: "data leak",
			Remediation: "aws s3api put-public-access-block ...", PoC: "aws s3api list-objects-v2 --bucket my-bucket --no-sign-request",
			Reachable:  findings.ReachUnknown,
			Compliance: []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.1.4"}},
			References: []string{"https://example.com/doc"},
		},
		{
			ID: "f2", CheckID: "aws_iam_root_mfa_disabled", Title: "Root account does not have MFA enabled",
			Severity: findings.SeverityCritical, Status: findings.StatusOpen, Provider: "aws", Service: "iam",
			Resource:    findings.Resource{ID: "account:111", Type: "aws_account"},
			Description: "Root MFA off",
		},
	}
}

func TestCSVExport(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, sampleFindings()); err != nil {
		t.Fatalf("CSV: %v", err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(records) != 3 { // header + 2 rows
		t.Fatalf("expected 3 rows, got %d", len(records))
	}
	if records[0][0] != "severity" || records[0][3] != "title" {
		t.Fatalf("unexpected header: %v", records[0])
	}
	if records[1][0] != "high" || records[1][7] != "my-bucket" {
		t.Fatalf("unexpected first data row: %v", records[1])
	}
}

func TestCSVEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, nil); err != nil {
		t.Fatalf("CSV: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "severity,") {
		t.Fatalf("expected header even when empty, got: %q", buf.String())
	}
}

func TestCSVFormulaInjectionNeutralized(t *testing.T) {
	// A resource named with a leading formula trigger (attacker-controlled via
	// the scanned account) must be written as text, not a live formula.
	fs := []findings.Finding{
		{
			ID: "x", CheckID: "c", Title: "t", Severity: findings.SeverityLow, Service: "s3",
			Resource: findings.Resource{ID: `=cmd|'/c calc'!A1`, Type: "aws_s3_bucket"},
		},
	}
	var buf bytes.Buffer
	if err := CSV(&buf, fs); err != nil {
		t.Fatalf("CSV: %v", err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	got := records[1][7] // resource_id column
	if got != `'=cmd|'/c calc'!A1` {
		t.Fatalf("resource_id not neutralized: %q", got)
	}
	if got[0] == '=' {
		t.Fatal("cell still begins with a formula trigger")
	}
}

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		"":           "",
		"normal":     "normal",
		"=SUM(A1)":   "'=SUM(A1)",
		"+1":         "'+1",
		"-1":         "'-1",
		"@x":         "'@x",
		"us-east-1":  "us-east-1", // hyphen mid-string is fine; only leading triggers
		"\t=evil":    "'\t=evil",
		"arn:aws:s3": "arn:aws:s3",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSARIFExport(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleFindings(), time.Now()); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", doc.Version)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "nubicustos" {
		t.Fatalf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	// ruleIndex must point at the matching rule.
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Fatalf("ruleIndex %d does not match ruleId %q", r.RuleIndex, r.RuleID)
		}
	}
	// critical/high both map to error level.
	for _, r := range run.Results {
		if r.Level != "error" {
			t.Fatalf("expected error level for %s, got %s", r.RuleID, r.Level)
		}
	}
}

func TestSARIFDeduplicatesRules(t *testing.T) {
	// Two findings sharing a check id should produce one rule, two results.
	fs := []findings.Finding{
		{ID: "a", CheckID: "dup", Title: "dup", Severity: findings.SeverityLow, Service: "s3"},
		{ID: "b", CheckID: "dup", Title: "dup", Severity: findings.SeverityLow, Service: "s3"},
	}
	rules, index := sarifRules(fs)
	if len(rules) != 1 {
		t.Fatalf("expected 1 deduped rule, got %d", len(rules))
	}
	if index["dup"] != 0 {
		t.Fatalf("expected dup rule at index 0, got %d", index["dup"])
	}
}

func TestHTMLExport(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, "aws", "111122223333", sampleFindings(), time.Now()); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"S3 bucket is publicly accessible",
		"Root account does not have MFA enabled",
		"111122223333",
		"sev-critical",
		"aws s3api list-objects-v2", // PoC rendered
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML output missing %q", want)
		}
	}
}

func TestHTMLEscaping(t *testing.T) {
	var buf bytes.Buffer
	fs := []findings.Finding{
		{ID: "x", CheckID: "c", Title: "<script>alert(1)</script>", Severity: findings.SeverityLow, Service: "s3"},
	}
	if err := HTML(&buf, "aws", "", fs, time.Now()); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Fatal("title was not HTML-escaped")
	}
}
