package web

import (
	"testing"

	// Register the check catalog so the compliance endpoint's engine.Checks()
	// returns the real specs.
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/k8s"
)

func TestComplianceEndpoint(t *testing.T) {
	s := seededServer(t)

	// Default framework (soc2) over the seeded scan: populated, with failures
	// from the seeded open findings (public S3, root MFA off).
	code, v := getJSON(t, s, "/api/v1/scans/scan-1/compliance")
	if code != 200 {
		t.Fatalf("compliance status %d", code)
	}
	if v["framework"] != "soc2" {
		t.Fatalf("default framework should be soc2, got %v", v["framework"])
	}
	if covered, _ := v["covered_controls"].(float64); covered == 0 {
		t.Fatalf("expected covered controls, got %v", v["covered_controls"])
	}
	if failing, _ := v["failing_controls"].(float64); failing == 0 {
		t.Error("seeded open findings should fail at least one control")
	}

	// Explicit framework.
	if code, v := getJSON(t, s, "/api/v1/scans/scan-1/compliance?framework=nist"); code != 200 || v["framework"] != "nist" {
		t.Fatalf("nist framework request failed: code=%d v=%v", code, v)
	}

	// Invalid framework → 400.
	if code, _ := getJSON(t, s, "/api/v1/scans/scan-1/compliance?framework=hipaa"); code != 400 {
		t.Fatalf("invalid framework should be 400, got %d", code)
	}
}
