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

func assertSkippedInOrder(t *testing.T, ms []Manifest, results []RunResult) {
	t.Helper()
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

func TestRunAvailableSequentialSkipsAbsentInOrder(t *testing.T) {
	ms := absentManifests()
	assertSkippedInOrder(t, ms, runAvailable(context.Background(), ".", ms, 1))
}

func TestRunAvailableConcurrentPreservesOrder(t *testing.T) {
	// Even with a concurrency bound above the tool count, results stay in input
	// order regardless of completion order.
	ms := absentManifests()
	assertSkippedInOrder(t, ms, runAvailable(context.Background(), ".", ms, 8))
}

func TestRunAvailableClampsConcurrency(t *testing.T) {
	// A non-positive concurrency is clamped to sequential, never a deadlock.
	ms := absentManifests()
	assertSkippedInOrder(t, ms, runAvailable(context.Background(), ".", ms, 0))
}

func TestRunAvailableStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the sweep starts
	if results := runAvailable(ctx, ".", absentManifests(), DefaultSweepConcurrency); len(results) != 0 {
		t.Fatalf("a cancelled context must stop the sweep before any tool, got %d results", len(results))
	}
}

func TestRunAvailableEmptySet(t *testing.T) {
	if results := runAvailable(context.Background(), ".", nil, DefaultSweepConcurrency); len(results) != 0 {
		t.Fatalf("an empty tool set yields no results, got %d", len(results))
	}
}
