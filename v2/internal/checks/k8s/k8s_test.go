package k8s

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func stateWith(k *state.K8s) *state.State {
	st := state.New()
	st.K8s = k
	return st
}

func evalCheck(t *testing.T, c engine.Check, st *state.State) []findings.Finding {
	t.Helper()
	fs, err := c.Evaluate(&engine.ScanContext{Provider: "k8s"}, st)
	if err != nil {
		t.Fatalf("%s: %v", c.Spec().ID, err)
	}
	return fs
}

func TestPrivilegedContainer(t *testing.T) {
	st := stateWith(&state.K8s{Pods: []state.K8sPod{
		{Name: "p1", Namespace: "default", Context: "kind", Containers: []state.K8sContainer{
			{Name: "app", Privileged: true, AllowPrivilegeEscalation: true, RunAsNonRoot: true},
			{Name: "side", Privileged: false, RunAsNonRoot: true},
		}},
	}})
	fs := evalCheck(t, privilegedContainer{}, st)
	if len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("only the privileged container should be flagged high, got %+v", fs)
	}
}

func TestHostNamespaces(t *testing.T) {
	st := stateWith(&state.K8s{Pods: []state.K8sPod{
		{Name: "host", Namespace: "default", HostPID: true, Containers: []state.K8sContainer{{Name: "c", RunAsNonRoot: true, AllowPrivilegeEscalation: false}}},
		{Name: "clean", Namespace: "default", Containers: []state.K8sContainer{{Name: "c", RunAsNonRoot: true, AllowPrivilegeEscalation: false}}},
	}})
	fs := evalCheck(t, hostNamespaces{}, st)
	if len(fs) != 1 || fs[0].Resource.Name != "host" {
		t.Fatalf("only the host-namespace pod should be flagged, got %+v", fs)
	}
}

func TestPrivilegeEscalation(t *testing.T) {
	st := stateWith(&state.K8s{Pods: []state.K8sPod{
		{Name: "p", Namespace: "default", Containers: []state.K8sContainer{
			{Name: "esc", AllowPrivilegeEscalation: true, RunAsNonRoot: true},
			{Name: "safe", AllowPrivilegeEscalation: false, RunAsNonRoot: true},
			{Name: "priv", Privileged: true, AllowPrivilegeEscalation: true, RunAsNonRoot: true}, // covered by privileged check, not here
		}},
	}})
	fs := evalCheck(t, privilegeEscalation{}, st)
	if len(fs) != 1 {
		t.Fatalf("only the non-privileged escalation-allowed container should be flagged, got %d: %+v", len(fs), fs)
	}
}

func TestRunAsRoot(t *testing.T) {
	st := stateWith(&state.K8s{Pods: []state.K8sPod{
		{Name: "p", Namespace: "default", Containers: []state.K8sContainer{
			{Name: "root", RunAsNonRoot: false, AllowPrivilegeEscalation: false},
			{Name: "nonroot", RunAsNonRoot: true, AllowPrivilegeEscalation: false},
		}},
	}})
	fs := evalCheck(t, runAsRoot{}, st)
	if len(fs) != 1 {
		t.Fatalf("only the run-as-root container should be flagged, got %d", len(fs))
	}
}

func TestClusterAdminBindingBroadSubject(t *testing.T) {
	st := stateWith(&state.K8s{Bindings: []state.RBACBinding{
		{Name: "bad", Context: "kind", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", Subjects: []string{"Group/system:authenticated"}},
		{Name: "named", Context: "kind", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", Subjects: []string{"User/alice"}},
		{Name: "other", Context: "kind", Kind: "ClusterRoleBinding", RoleRef: "view", Subjects: []string{"Group/system:authenticated"}},
	}})
	fs := evalCheck(t, clusterAdminBinding{}, st)
	if len(fs) != 1 || fs[0].Resource.Name != "bad" {
		t.Fatalf("only cluster-admin bound to a broad subject should be flagged (critical), got %+v", fs)
	}
	if fs[0].Severity != findings.SeverityCritical {
		t.Fatalf("expected critical, got %s", fs[0].Severity)
	}
}

func TestClusterAdminEquivalentCustomRole(t *testing.T) {
	// A custom ClusterRole that is verb-* on resource-*, bound to a broad subject,
	// must be flagged critical even though its name is not "cluster-admin".
	st := stateWith(&state.K8s{
		Roles: []state.K8sRole{
			{Name: "godmode", Context: "kind", Kind: "ClusterRole", WildcardVerb: true, WildcardResource: true},
		},
		Bindings: []state.RBACBinding{
			{Name: "b", Context: "kind", Kind: "ClusterRoleBinding", RoleRef: "godmode", Subjects: []string{"Group/system:authenticated"}},
		},
	})
	fs := evalCheck(t, clusterAdminBinding{}, st)
	if len(fs) != 1 || fs[0].Severity != findings.SeverityCritical {
		t.Fatalf("custom cluster-admin-equivalent role bound broadly should be critical, got %+v", fs)
	}
}

func TestClusterAdminNamespacedServiceAccountsGroup(t *testing.T) {
	st := stateWith(&state.K8s{Bindings: []state.RBACBinding{
		{Name: "b", Context: "kind", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin",
			Subjects: []string{"Group/system:serviceaccounts:kube-system"}},
	}})
	if fs := evalCheck(t, clusterAdminBinding{}, st); len(fs) != 1 {
		t.Fatalf("cluster-admin bound to a namespace's all-SAs group must be flagged, got %d", len(fs))
	}
}

func TestWildcardRole(t *testing.T) {
	st := stateWith(&state.K8s{Roles: []state.K8sRole{
		{Name: "godmode", Context: "kind", Kind: "ClusterRole", WildcardVerb: true, WildcardResource: true},
		{Name: "verbs-only", Context: "kind", Kind: "ClusterRole", WildcardVerb: true, WildcardResource: false},
		{Name: "scoped", Context: "kind", Kind: "Role", Namespace: "default"},
	}})
	fs := evalCheck(t, wildcardRole{}, st)
	if len(fs) != 1 || fs[0].Resource.Name != "godmode" {
		t.Fatalf("only the verb-*-on-resource-* role should be flagged, got %+v", fs)
	}
}

func TestK8sExposedSecret(t *testing.T) {
	st := stateWith(&state.K8s{SecretHits: []state.SecretHit{
		{Detector: "generic_secret", Kind: "secret", Surface: "k8s_configmap", Resource: "default/app-config", Account: "ctx-a", Locator: "DB_PASSWORD", Masked: "****1234"},
		{Detector: "aws_access_key_id", Kind: "AWS key", Surface: "k8s_pod_env", Resource: "default/web-0", Account: "ctx-a", Locator: "web:AWS_KEY", Masked: "****abcd"},
	}})
	fs := evalCheck(t, exposedSecret{}, st)
	if len(fs) != 1 { // one aggregate per context
		t.Fatalf("expected one aggregate finding for ctx-a, got %d: %+v", len(fs), fs)
	}
	if fs[0].Severity != findings.SeverityHigh {
		t.Errorf("exposed-secret should be high severity, got %s", fs[0].Severity)
	}
	if got := evalCheck(t, exposedSecret{}, stateWith(&state.K8s{})); len(got) != 0 {
		t.Fatalf("no secret hits should yield no findings, got %d", len(got))
	}
}

func TestNilK8sStateNoPanic(t *testing.T) {
	st := state.New()
	st.K8s = nil
	for _, c := range []engine.Check{privilegedContainer{}, hostNamespaces{}, privilegeEscalation{}, runAsRoot{}, clusterAdminBinding{}, wildcardRole{}, exposedSecret{}} {
		if fs := evalCheck(t, c, st); len(fs) != 0 {
			t.Fatalf("%s on nil k8s state should yield nothing, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestHostNamespacesHelper(t *testing.T) {
	if (state.K8sPod{}).HostNamespaces() {
		t.Fatal("a pod with no host namespaces should report false")
	}
	if !(state.K8sPod{HostIPC: true}).HostNamespaces() {
		t.Fatal("hostIPC should report true")
	}
}
