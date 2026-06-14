package preflight

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// k8sRemediator renders access gaps as a Kubernetes RBAC fix: a generated
// ClusterRole granting exactly the missing verbs/resources (ready for `kubectl
// apply -f`), to be bound to the scan identity with a ClusterRoleBinding.
type k8sRemediator struct{}

// NewK8sRemediator returns the Kubernetes RBAC remediator.
func NewK8sRemediator() Remediator { return k8sRemediator{} }

func (k8sRemediator) Build(t Tool, tr ToolReport) Remediation {
	rem := Remediation{
		PolicyName:      t.RemediationPolicyName,
		ManagedPolicies: append([]string(nil), t.RequiredManagedPolicies...), // built-in ClusterRole names
	}
	if tr.Readiness == ReadinessReady {
		rem.Summary = fmt.Sprintf("%s: all %d required permission(s) present — ready.", t.Name, len(tr.Allowed))
		return rem
	}

	missing := append([]string(nil), tr.Denied...)
	sort.Strings(missing)
	if len(missing) > 0 {
		rem.PolicyDocument = k8sClusterRole(t.RemediationPolicyName, missing)
	}

	var parts []string
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing %d permission(s) — apply the generated %s ClusterRole and bind it to the scan identity with a ClusterRoleBinding", len(missing), t.RemediationPolicyName))
	}
	if len(tr.Unknown) > 0 {
		parts = append(parts, fmt.Sprintf("%d permission(s) could not be verified (SelfSubjectAccessReview did not complete)", len(tr.Unknown)))
	}
	rem.Summary = fmt.Sprintf("%s [%s]: %s.", t.Name, tr.Readiness, strings.Join(parts, "; "))
	return rem
}

// k8sClusterRole renders a ClusterRole granting exactly the missing actions,
// grouped into one rule per apiGroup. Output is JSON, which `kubectl apply -f`
// accepts as a manifest.
func k8sClusterRole(name string, missingDisplays []string) string {
	if name == "" {
		name = "nubicustos-scan-reader"
	}

	// Group resources and verbs by apiGroup, preserving determinism.
	type ruleAcc struct {
		resources map[string]bool
		verbs     map[string]bool
	}
	byGroup := map[string]*ruleAcc{}
	var groupOrder []string
	for _, d := range missingDisplays {
		a, ok := k8sActionByDisplay(d)
		if !ok {
			continue
		}
		acc := byGroup[a.Group]
		if acc == nil {
			acc = &ruleAcc{resources: map[string]bool{}, verbs: map[string]bool{}}
			byGroup[a.Group] = acc
			groupOrder = append(groupOrder, a.Group)
		}
		acc.resources[a.Resource] = true
		acc.verbs[a.Verb] = true
	}
	sort.Strings(groupOrder)

	rules := make([]map[string]any, 0, len(groupOrder))
	for _, g := range groupOrder {
		acc := byGroup[g]
		rules = append(rules, map[string]any{
			"apiGroups": []string{g},
			"resources": sortedKeys(acc.resources),
			"verbs":     sortedKeys(acc.verbs),
		})
	}

	doc := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": name},
		"rules":      rules,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
