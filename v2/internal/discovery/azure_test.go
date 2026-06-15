package discovery

import (
	"context"
	"testing"
)

type fakeAzureLister struct{ subs []azureSub }

func (f fakeAzureLister) listSubscriptions(context.Context) ([]azureSub, error) { return f.subs, nil }

type fakeMGLister struct{ ids map[string]bool }

func (f fakeMGLister) subsUnderManagementGroup(context.Context, string) (map[string]bool, error) {
	return f.ids, nil
}

func subSet(r *AzureResult) map[string]bool {
	m := map[string]bool{}
	for _, s := range r.Subscriptions {
		m[s.ID] = true
	}
	return m
}

func TestDiscoverAzure(t *testing.T) {
	all := []azureSub{
		{ID: "sub-a", Name: "Prod", State: "Enabled"},
		{ID: "sub-b", Name: "Dev", State: "Enabled"},
		{ID: "sub-c", Name: "Old", State: "Disabled"},
	}

	t.Run("whole estate skips disabled subscriptions", func(t *testing.T) {
		res, err := discoverAzure(context.Background(), fakeAzureLister{all}, nil, AzureOptions{})
		if err != nil {
			t.Fatal(err)
		}
		got := subSet(res)
		if !got["sub-a"] || !got["sub-b"] {
			t.Errorf("enabled subs missing: %v", got)
		}
		if got["sub-c"] {
			t.Error("disabled subscription must be skipped")
		}
		if len(res.Skipped) != 1 || res.Skipped[0].ID != "sub-c" {
			t.Errorf("expected sub-c skipped with reason, got %+v", res.Skipped)
		}
	})

	t.Run("allowlist narrows scope", func(t *testing.T) {
		res, _ := discoverAzure(context.Background(), fakeAzureLister{all}, nil, AzureOptions{Subscriptions: []string{"sub-b"}})
		if len(res.Subscriptions) != 1 || res.Subscriptions[0].ID != "sub-b" {
			t.Errorf("allowlist should select only sub-b, got %+v", res.Subscriptions)
		}
	})

	t.Run("exclude removes an enabled subscription", func(t *testing.T) {
		res, _ := discoverAzure(context.Background(), fakeAzureLister{all}, nil, AzureOptions{Exclude: []string{"sub-a"}})
		if subSet(res)["sub-a"] {
			t.Error("sub-a should be excluded")
		}
		if !hasSkip(res, "sub-a", "excluded") {
			t.Errorf("sub-a should be skipped as excluded: %+v", res.Skipped)
		}
	})

	t.Run("management-group scoping restricts to the subtree", func(t *testing.T) {
		mg := fakeMGLister{ids: map[string]bool{"sub-a": true}}
		res, err := discoverAzure(context.Background(), fakeAzureLister{all}, mg, AzureOptions{ManagementGroup: "mg-prod"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Subscriptions) != 1 || res.Subscriptions[0].ID != "sub-a" {
			t.Errorf("only sub-a is under the MG, got %+v", res.Subscriptions)
		}
		if !hasSkip(res, "sub-b", "outside management group mg-prod") {
			t.Errorf("sub-b should be skipped as outside the MG: %+v", res.Skipped)
		}
	})

	t.Run("IDs returns in-scope ids", func(t *testing.T) {
		res, _ := discoverAzure(context.Background(), fakeAzureLister{all}, nil, AzureOptions{})
		ids := res.IDs()
		if len(ids) != 2 {
			t.Errorf("expected 2 in-scope ids, got %v", ids)
		}
	})
}

func hasSkip(r *AzureResult, id, reason string) bool {
	for _, s := range r.Skipped {
		if s.ID == id && s.Reason == reason {
			return true
		}
	}
	return false
}
