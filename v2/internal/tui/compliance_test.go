package tui

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"

	// Register the check catalog so engine.Checks() (used by the compliance view)
	// returns the real specs.
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/k8s"
)

func TestComplianceViewRendersAndFlagsFailures(t *testing.T) {
	d := Data{
		ScanID: "s1", Provider: "aws", Account: "111122223333",
		Findings: []findings.Finding{
			{ID: "f1", CheckID: "aws_s3_public_access", Severity: findings.SeverityHigh, Service: "s3"},
		},
	}
	m := send(New(d, nil), key("4")) // compliance view
	if m.view != viewCompliance {
		t.Fatalf("key 4 should select the compliance view, got %d", m.view)
	}
	out := m.View()
	for _, want := range []string{"SOC 2", "PCI-DSS", "NIST", "FAIL"} {
		if !strings.Contains(out, want) {
			t.Fatalf("compliance view should contain %q:\n%s", want, out)
		}
	}
}
