package engine

import (
	"context"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

type fakeCheck struct{}

func (fakeCheck) Spec() findings.CheckSpec {
	return findings.CheckSpec{ID: "test_check", Title: "fake", Provider: "test", Service: "x", Severity: findings.SeverityMedium}
}

func (fakeCheck) Evaluate(_ *ScanContext, _ *state.State) ([]findings.Finding, error) {
	return []findings.Finding{{
		ID: "f1", CheckID: "test_check", Title: "fake", Severity: findings.SeverityMedium, Status: findings.StatusOpen,
	}}, nil
}

// TestRunEmitsFindings proves the registry → check → result pipeline works
// without any cloud calls.
func TestRunEmitsFindings(t *testing.T) {
	RegisterCheck(fakeCheck{})
	r := Run(&ScanContext{Ctx: context.Background(), Provider: "test"})

	for _, f := range r.Findings {
		if f.ID == "f1" {
			return
		}
	}
	t.Fatalf("expected fake finding f1 in results, got %+v", r.Findings)
}

// TestConcurrencyBound keeps the worker-pool sizing sane on any host.
func TestConcurrencyBound(t *testing.T) {
	if n := concurrency(); n < 1 || n > 16 {
		t.Fatalf("concurrency out of bounds: %d", n)
	}
}
