package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestK8sProberMapsActionsThroughReview(t *testing.T) {
	// Allow pods, deny roles, error on rolebindings; unknown action stays unknown.
	p := &k8sProber{review: func(_ context.Context, verb, group, resource string) (bool, error) {
		switch resource {
		case "pods":
			return true, nil
		case "roles":
			return false, nil
		case "rolebindings":
			return false, errors.New("connection refused")
		}
		return false, nil
	}}
	if got := p.Probe(context.Background(), "list pods"); got != DecisionAllowed {
		t.Errorf("allowed review should be allowed, got %s", got)
	}
	if got := p.Probe(context.Background(), "list roles.rbac.authorization.k8s.io"); got != DecisionDenied {
		t.Errorf("disallowed review should be denied, got %s", got)
	}
	if got := p.Probe(context.Background(), "list rolebindings.rbac.authorization.k8s.io"); got != DecisionUnknown {
		t.Errorf("a review error should be unknown, got %s", got)
	}
	if got := p.Probe(context.Background(), "delete secrets"); got != DecisionUnknown {
		t.Errorf("an unknown action should be unknown, got %s", got)
	}
}

func TestK8sRemediatorEmitsClusterRoleGroupedByApiGroup(t *testing.T) {
	tr := ToolReport{
		Readiness: ReadinessPartial,
		Allowed:   []string{"list pods"},
		Denied: []string{
			"list roles.rbac.authorization.k8s.io",
			"list clusterroles.rbac.authorization.k8s.io",
		},
	}
	rem := NewK8sRemediator().Build(K8sTools[0], tr)
	doc := rem.PolicyDocument
	if !strings.Contains(doc, `"kind": "ClusterRole"`) {
		t.Errorf("document should be a ClusterRole manifest:\n%s", doc)
	}
	if !strings.Contains(doc, "rbac.authorization.k8s.io") || !strings.Contains(doc, "clusterroles") {
		t.Errorf("ClusterRole must grant the missing RBAC resources:\n%s", doc)
	}
	// pods was allowed, so it must not appear in the generated role.
	if strings.Contains(doc, `"pods"`) {
		t.Errorf("ClusterRole must NOT include already-allowed resources:\n%s", doc)
	}
	if !strings.Contains(rem.Summary, "ClusterRoleBinding") {
		t.Errorf("summary should explain binding the role: %q", rem.Summary)
	}
}

func TestEvaluateK8sProbeOnly(t *testing.T) {
	allow := map[string]Decision{}
	for _, a := range k8sActionDisplays() {
		allow[a] = DecisionAllowed
	}
	rep := Evaluate(context.Background(), Options{
		Provider:   "k8s",
		Account:    "ctx-1",
		Tools:      K8sTools,
		Prober:     fakeProbe{d: allow},
		Remediator: NewK8sRemediator(),
	})
	if rep.Overall != ReadinessReady {
		t.Fatalf("all-allowed Kubernetes check should be ready, got %s", rep.Overall)
	}
	if rep.Tools[0].Remediate.PolicyDocument != "" {
		t.Error("ready Kubernetes tool needs no ClusterRole")
	}
}

func TestK8sCatalogRoundTrip(t *testing.T) {
	if _, ok := K8sToolByKey("nubicustos"); !ok {
		t.Fatal("native Kubernetes tool must be in the catalog")
	}
	for _, d := range k8sActionDisplays() {
		a, ok := k8sActionByDisplay(d)
		if !ok || a.Verb == "" || a.Resource == "" {
			t.Errorf("action %q must resolve to complete resource attributes, got %+v", d, a)
		}
	}
}
