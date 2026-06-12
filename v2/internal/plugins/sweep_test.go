package plugins

import (
	"context"
	"testing"
)

// absent manifests use binaries guaranteed not to be on PATH, so the sweep's
// availability/skip/ordering logic is deterministic without installing tools.
func absentManifests() []Manifest {
	return []Manifest{
		{Name: "alpha", Binary: "nubicustos-absent-alpha-xyz", Service: "test", Format: FormatTrivy},
		{Name: "beta", Binary: "nubicustos-absent-beta-xyz", Service: "test", Format: FormatGrype},
		{Name: "gamma", Binary: "nubicustos-absent-gamma-xyz", Service: "test", Format: FormatCheckov},
	}
}

func TestRunAvailableSkipsAbsentToolsInOrder(t *testing.T) {
	ms := absentManifests()
	results := runAvailable(context.Background(), ".", ms)

	if len(results) != len(ms) {
		t.Fatalf("every tool must be reported (skips included): got %d, want %d", len(results), len(ms))
	}
	for i, r := range results {
		if r.Manifest.Name != ms[i].Name {
			t.Fatalf("result %d out of order: got %q, want %q", i, r.Manifest.Name, ms[i].Name)
		}
		if r.Available {
			t.Fatalf("%s should be unavailable", r.Manifest.Name)
		}
		if r.Err != nil {
			t.Fatalf("a skipped (not-run) tool must not carry a run error, got %v", r.Err)
		}
		if !r.StartedAt.IsZero() || !r.FinishedAt.IsZero() {
			t.Fatalf("a skipped tool must not be timed, got start=%v finish=%v", r.StartedAt, r.FinishedAt)
		}
	}
}

func TestRunAvailableStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the sweep starts
	results := runAvailable(ctx, ".", absentManifests())
	if len(results) != 0 {
		t.Fatalf("a cancelled context must stop the sweep before any tool, got %d results", len(results))
	}
}

func TestRunAvailableEmptySet(t *testing.T) {
	if results := runAvailable(context.Background(), ".", nil); len(results) != 0 {
		t.Fatalf("an empty tool set yields no results, got %d", len(results))
	}
}
