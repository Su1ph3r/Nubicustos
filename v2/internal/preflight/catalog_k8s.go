package preflight

// k8sAction is one Kubernetes access requirement: a human-readable display
// string (what appears in the report and a tool's RequiredActions) paired with
// the resource attributes a SelfSubjectAccessReview needs to verify it.
type k8sAction struct {
	Display  string // e.g. "list pods", "list roles.rbac.authorization.k8s.io"
	Verb     string
	Group    string // "" for the core API group
	Resource string
}

// k8sActions enumerates the access the native Kubernetes collectors invoke,
// derived from internal/providers/k8s (pod listing + RBAC role/binding listing).
// Keep in sync when a collector adds an API call.
var k8sActions = []k8sAction{
	{Display: "list pods", Verb: "list", Group: "", Resource: "pods"},
	{Display: "list configmaps", Verb: "list", Group: "", Resource: "configmaps"},
	{Display: "list roles.rbac.authorization.k8s.io", Verb: "list", Group: "rbac.authorization.k8s.io", Resource: "roles"},
	{Display: "list clusterroles.rbac.authorization.k8s.io", Verb: "list", Group: "rbac.authorization.k8s.io", Resource: "clusterroles"},
	{Display: "list rolebindings.rbac.authorization.k8s.io", Verb: "list", Group: "rbac.authorization.k8s.io", Resource: "rolebindings"},
	{Display: "list clusterrolebindings.rbac.authorization.k8s.io", Verb: "list", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"},
}

// k8sActionDisplays returns just the display strings, for a Tool's RequiredActions.
func k8sActionDisplays() []string {
	out := make([]string, len(k8sActions))
	for i, a := range k8sActions {
		out[i] = a.Display
	}
	return out
}

// K8sTools is the requirement catalog for Kubernetes scanning. The built-in
// `view` ClusterRole covers pod reads but deliberately excludes RBAC objects, so
// the generated custom ClusterRole grants the role/binding listing the scan needs.
var K8sTools = []Tool{
	{
		Key: "nubicustos", Name: "Nubicustos (native Kubernetes checks)",
		Description:             "The built-in read-only Kubernetes posture engine (pod security, RBAC)",
		RequiredManagedPolicies: []string{"view (built-in ClusterRole)"},
		RequiredActions:         k8sActionDisplays(),
		RemediationPolicyName:   "nubicustos-scan-reader",
	},
}

// K8sToolByKey returns the Kubernetes catalog entry for key (ok=false if unknown).
func K8sToolByKey(key string) (Tool, bool) {
	for _, t := range K8sTools {
		if t.Key == key {
			return t, true
		}
	}
	return Tool{}, false
}

// k8sActionByDisplay resolves a display string back to its resource attributes.
func k8sActionByDisplay(display string) (k8sAction, bool) {
	for _, a := range k8sActions {
		if a.Display == display {
			return a, true
		}
	}
	return k8sAction{}, false
}
