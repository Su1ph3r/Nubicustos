package plugins

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func manifest(format Format) Manifest {
	return Manifest{Name: string(format), Binary: string(format), Service: "test", Format: format}
}

func TestAvailableFalseForMissingBinary(t *testing.T) {
	m := Manifest{Name: "definitely-not-installed", Binary: "nubicustos-no-such-binary-xyz"}
	if Available(m) {
		t.Fatal("a nonexistent binary must not report as available")
	}
}

func TestLookupBuiltins(t *testing.T) {
	for _, name := range []string{"trivy", "grype", "checkov", "terrascan", "kube-bench"} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("expected built-in manifest for %q", name)
		}
	}
	if _, ok := Lookup("pacu"); ok {
		t.Fatal("pacu must not be a built-in tool")
	}
}

func TestParseEmptyOutput(t *testing.T) {
	fs, err := Parse(manifest(FormatTrivy), []byte("   "))
	if err != nil || fs != nil {
		t.Fatalf("empty output should yield no findings and no error, got %d / %v", len(fs), err)
	}
}

func TestParseTrivy(t *testing.T) {
	raw := []byte(`{"Results":[
	  {"Target":"app/go.mod","Vulnerabilities":[
	    {"VulnerabilityID":"CVE-2024-1","PkgName":"libfoo","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"CRITICAL","Title":"rce in libfoo","Description":"bad"}
	  ]},
	  {"Target":"Dockerfile","Misconfigurations":[
	    {"ID":"DS002","Title":"root user","Severity":"HIGH","Description":"runs as root","Resolution":"add USER"}
	  ]}
	]}`)
	fs, err := parseTrivy(manifest(FormatTrivy), raw)
	if err != nil {
		t.Fatalf("parseTrivy: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	if fs[0].Severity != findings.SeverityCritical || fs[0].CheckID != "trivy:CVE-2024-1" {
		t.Fatalf("unexpected vuln finding: %+v", fs[0])
	}
	if fs[1].Severity != findings.SeverityHigh || fs[1].Resource.Type != "misconfiguration" {
		t.Fatalf("unexpected misconfig finding: %+v", fs[1])
	}
	if fs[0].Provider != "trivy" {
		t.Fatalf("provider should be the tool name, got %q", fs[0].Provider)
	}
}

func TestParseGrype(t *testing.T) {
	raw := []byte(`{"matches":[{"vulnerability":{"id":"CVE-2024-2","severity":"High","description":"x"},"artifact":{"name":"openssl","version":"1.1.1"}}]}`)
	fs, err := parseGrype(manifest(FormatGrype), raw)
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	if len(fs) != 1 || fs[0].Severity != findings.SeverityHigh || fs[0].Resource.ID != "openssl@1.1.1" {
		t.Fatalf("unexpected grype finding: %+v", fs)
	}
}

func TestParseCheckovSingleAndArray(t *testing.T) {
	single := []byte(`{"results":{"failed_checks":[{"check_id":"CKV_AWS_1","check_name":"S3 not encrypted","severity":"MEDIUM","file_path":"/main.tf","resource":"aws_s3_bucket.b"}]}}`)
	fs, err := parseCheckov(manifest(FormatCheckov), single)
	if err != nil || len(fs) != 1 || fs[0].CheckID != "checkov:CKV_AWS_1" {
		t.Fatalf("single checkov doc parse failed: %d / %v", len(fs), err)
	}
	array := []byte(`[{"results":{"failed_checks":[{"check_id":"CKV_AWS_2","check_name":"x","severity":"LOW","resource":"r"}]}},{"results":{"failed_checks":[]}}]`)
	fs, err = parseCheckov(manifest(FormatCheckov), array)
	if err != nil || len(fs) != 1 || fs[0].Severity != findings.SeverityLow {
		t.Fatalf("array checkov doc parse failed: %d / %v", len(fs), err)
	}
}

func TestParseTerrascan(t *testing.T) {
	raw := []byte(`{"results":{"violations":[{"rule_name":"AC_AWS_1","description":"public bucket","severity":"HIGH","resource_name":"b","resource_type":"aws_s3_bucket","file":"main.tf"}]}}`)
	fs, err := parseTerrascan(manifest(FormatTerrascan), raw)
	if err != nil || len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("terrascan parse failed: %d / %v / %+v", len(fs), err, fs)
	}
}

func TestParseKubeBenchSkipsPass(t *testing.T) {
	raw := []byte(`{"Controls":[{"tests":[{"results":[
	  {"test_number":"1.1.1","test_desc":"perms","status":"FAIL","remediation":"chmod"},
	  {"test_number":"1.1.2","test_desc":"ok","status":"PASS"},
	  {"test_number":"1.1.3","test_desc":"maybe","status":"WARN"}
	]}]}]}`)
	fs, err := parseKubeBench(manifest(FormatKubeBench), raw)
	if err != nil {
		t.Fatalf("parseKubeBench: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings (FAIL+WARN, PASS skipped), got %d", len(fs))
	}
	// FAIL -> high, WARN -> low.
	var fail, warn findings.Severity
	for _, f := range fs {
		if f.CheckID == "kube-bench:1.1.1" {
			fail = f.Severity
		}
		if f.CheckID == "kube-bench:1.1.3" {
			warn = f.Severity
		}
	}
	if fail != findings.SeverityHigh || warn != findings.SeverityLow {
		t.Fatalf("status->severity mapping wrong: fail=%s warn=%s", fail, warn)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]findings.Severity{
		"CRITICAL":      findings.SeverityCritical,
		"High":          findings.SeverityHigh,
		"moderate":      findings.SeverityMedium,
		"negligible":    findings.SeverityInfo,
		"weird-unknown": findings.SeverityMedium, // unknown falls back to medium (never dropped)
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseBadJSONErrors(t *testing.T) {
	if _, err := parseTrivy(manifest(FormatTrivy), []byte("not json")); err == nil {
		t.Fatal("malformed trivy output should return an error (not be silently dropped)")
	}
}
