package preflight

import (
	"context"
	"strings"
	"testing"
)

func TestGCPProberServesBatchResult(t *testing.T) {
	// Two of three queried permissions granted; one denied; an unqueried action unknown.
	p := &gcpProber{
		ok: true,
		queried: map[string]bool{
			"storage.buckets.list":         true,
			"storage.buckets.getIamPolicy": true,
			"compute.firewalls.list":       true,
		},
		granted: map[string]bool{
			"storage.buckets.list":   true,
			"compute.firewalls.list": true,
		},
	}
	if got := p.Probe(context.Background(), "storage.buckets.list"); got != DecisionAllowed {
		t.Errorf("granted permission should be allowed, got %s", got)
	}
	if got := p.Probe(context.Background(), "storage.buckets.getIamPolicy"); got != DecisionDenied {
		t.Errorf("queried-but-ungranted permission should be denied, got %s", got)
	}
	if got := p.Probe(context.Background(), "bigquery.datasets.get"); got != DecisionUnknown {
		t.Errorf("unqueried permission should be unknown, got %s", got)
	}
}

func TestGCPProberCheckFailedIsAllUnknown(t *testing.T) {
	p := &gcpProber{ok: false, queried: map[string]bool{"storage.buckets.list": true}}
	if got := p.Probe(context.Background(), "storage.buckets.list"); got != DecisionUnknown {
		t.Errorf("when the permission check did not run, every action is unknown, got %s", got)
	}
}

func TestGCPRemediatorEmitsCustomRole(t *testing.T) {
	tr := ToolReport{
		Readiness: ReadinessPartial,
		Allowed:   []string{"storage.buckets.list"},
		Denied:    []string{"compute.firewalls.list"},
	}
	rem := NewGCPRemediator("proj-1").Build(GCPTools[0], tr)
	doc := rem.PolicyDocument
	if !strings.Contains(doc, "compute.firewalls.list") {
		t.Errorf("custom role must include the missing permission:\n%s", doc)
	}
	if strings.Contains(doc, "storage.buckets.list") {
		t.Errorf("custom role must NOT include already-allowed permissions:\n%s", doc)
	}
	if !strings.Contains(doc, "includedPermissions") {
		t.Errorf("document should be a GCP custom role definition:\n%s", doc)
	}
	if !strings.Contains(rem.Summary, "roles/iam.securityReviewer") {
		t.Errorf("summary should name the predefined roles: %q", rem.Summary)
	}
}

func TestEvaluateGCPProbeOnly(t *testing.T) {
	allow := map[string]Decision{}
	for _, p := range nubicustosGCPPermissions {
		allow[p] = DecisionAllowed
	}
	rep := Evaluate(context.Background(), Options{
		Provider:   "gcp",
		Account:    "proj-1",
		Tools:      GCPTools,
		Prober:     fakeProbe{d: allow},
		Remediator: NewGCPRemediator("proj-1"),
	})
	if rep.Overall != ReadinessReady {
		t.Fatalf("all-granted GCP check should be ready, got %s", rep.Overall)
	}
	if rep.Tools[0].Remediate.PolicyDocument != "" {
		t.Error("ready GCP tool needs no custom role")
	}
}

func TestGCPCatalogWellFormed(t *testing.T) {
	if _, ok := GCPToolByKey("nubicustos"); !ok {
		t.Fatal("native GCP tool must be in the catalog")
	}
	for _, p := range nubicustosGCPPermissions {
		if !strings.Contains(p, ".") {
			t.Errorf("malformed GCP permission %q", p)
		}
	}
}
