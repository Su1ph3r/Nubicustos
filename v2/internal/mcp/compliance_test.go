package mcp

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/compliance"

	// Register the full check catalog so engine.Checks() (used by the compliance
	// tool) returns the real specs.
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/k8s"
)

func TestComplianceReportTool(t *testing.T) {
	st, ctx := seed(t)

	// Unknown framework → error result.
	res, _ := complianceReport(st)(ctx, call(map[string]any{"framework": "hipaa"}))
	if !res.IsError {
		t.Fatal("an unsupported framework should return an error result")
	}

	// NIST report over the seeded scan: should have covered controls, and the
	// seeded findings (root MFA off, public S3) should fail their controls.
	res, _ = complianceReport(st)(ctx, call(map[string]any{"framework": "nist", "scan": "s1"}))
	var rep compliance.Report
	decode(t, res, &rep)
	if rep.Framework != "nist" || rep.Covered == 0 {
		t.Fatalf("expected a populated NIST report, got %+v", rep)
	}
	if rep.Failing == 0 {
		t.Error("seeded open findings (root MFA, public S3) should fail at least one control")
	}
}
