package discovery

import (
	"context"
	"testing"
)

type fakeGCPLister struct{ projs []gcpProj }

func (f fakeGCPLister) listProjects(context.Context) ([]gcpProj, error) { return f.projs, nil }

func projSet(r *GCPResult) map[string]bool {
	m := map[string]bool{}
	for _, p := range r.Projects {
		m[p.ID] = true
	}
	return m
}

func TestDiscoverGCP(t *testing.T) {
	all := []gcpProj{
		{ID: "proj-a", Name: "Prod", State: "ACTIVE"},
		{ID: "proj-b", Name: "Dev", State: "ACTIVE"},
		{ID: "proj-c", Name: "Old", State: "DELETE_REQUESTED"},
	}

	t.Run("whole estate skips non-active projects", func(t *testing.T) {
		res, err := discoverGCP(context.Background(), fakeGCPLister{all}, GCPOptions{})
		if err != nil {
			t.Fatal(err)
		}
		got := projSet(res)
		if !got["proj-a"] || !got["proj-b"] {
			t.Errorf("active projects missing: %v", got)
		}
		if got["proj-c"] {
			t.Error("non-active project must be skipped")
		}
		if len(res.Skipped) != 1 || res.Skipped[0].ID != "proj-c" {
			t.Errorf("expected proj-c skipped with reason, got %+v", res.Skipped)
		}
	})

	t.Run("allowlist narrows scope", func(t *testing.T) {
		res, _ := discoverGCP(context.Background(), fakeGCPLister{all}, GCPOptions{Projects: []string{"proj-b"}})
		if len(res.Projects) != 1 || res.Projects[0].ID != "proj-b" {
			t.Errorf("allowlist should select only proj-b, got %+v", res.Projects)
		}
	})

	t.Run("exclude removes an active project", func(t *testing.T) {
		res, _ := discoverGCP(context.Background(), fakeGCPLister{all}, GCPOptions{Exclude: []string{"proj-a"}})
		if projSet(res)["proj-a"] {
			t.Error("proj-a should be excluded")
		}
		var reason string
		for _, s := range res.Skipped {
			if s.ID == "proj-a" {
				reason = s.Reason
			}
		}
		if reason != "excluded" {
			t.Errorf("expected proj-a skipped with reason 'excluded', got %q (skipped=%+v)", reason, res.Skipped)
		}
	})

	t.Run("IDs returns sorted in-scope ids", func(t *testing.T) {
		res, _ := discoverGCP(context.Background(), fakeGCPLister{all}, GCPOptions{})
		ids := res.IDs()
		if len(ids) != 2 || ids[0] != "proj-a" || ids[1] != "proj-b" {
			t.Errorf("IDs() = %v, want [proj-a proj-b]", ids)
		}
	})
}
