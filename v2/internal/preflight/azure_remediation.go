package preflight

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// azureRemediator renders access gaps as an Azure RBAC fix: built-in roles to
// assign plus a least-privilege custom role definition granting exactly the
// missing ARM actions, scoped to the subscription. It is the Azure analogue of
// awsRemediator.
type azureRemediator struct {
	subscription string // scopes the generated custom role's AssignableScopes
}

// NewAzureRemediator returns the Azure RBAC remediator, scoping any generated
// custom role to subscription.
func NewAzureRemediator(subscription string) Remediator {
	return azureRemediator{subscription: subscription}
}

func (r azureRemediator) Build(t Tool, tr ToolReport) Remediation {
	rem := Remediation{
		PolicyName:      t.RemediationPolicyName,
		ManagedPolicies: append([]string(nil), t.RequiredManagedPolicies...), // Azure built-in role names
	}
	if tr.Readiness == ReadinessReady {
		rem.Summary = fmt.Sprintf("%s: all %d required permission(s) present — ready.", t.Name, len(tr.Allowed))
		return rem
	}

	// Azure preflight is probe-only, so there are no simulate/probe conflicts; the
	// gaps are genuinely-denied actions and actions that could not be verified.
	missing := append([]string(nil), tr.Denied...)
	sort.Strings(missing)
	if len(missing) > 0 {
		rem.PolicyDocument = customRole(t.RemediationPolicyName, missing, r.subscription)
	}

	var parts []string
	if len(missing) > 0 {
		fix := fmt.Sprintf("create and assign the generated %s custom role", t.RemediationPolicyName)
		if len(t.RequiredManagedPolicies) > 0 {
			fix = fmt.Sprintf("assign %s, or %s", strings.Join(t.RequiredManagedPolicies, " + "), fix)
		}
		parts = append(parts, fmt.Sprintf("missing %d permission(s) — %s", len(missing), fix))
	}
	if len(tr.Unknown) > 0 {
		parts = append(parts, fmt.Sprintf("%d permission(s) could not be verified (no resource of that type present to read) — coverage incomplete", len(tr.Unknown)))
	}
	rem.Summary = fmt.Sprintf("%s [%s]: %s.", t.Name, tr.Readiness, strings.Join(parts, "; "))
	return rem
}

// customRole renders an Azure custom role definition granting exactly actions,
// assignable at the subscription. The output is ready for
// `az role definition create --role-definition <file>`.
func customRole(name string, actions []string, subscription string) string {
	if name == "" {
		name = "NubicustosAzurePreflightRole"
	}
	scope := "/subscriptions/" + subscription
	if subscription == "" {
		scope = "/subscriptions/<subscription-id>"
	}
	doc := map[string]any{
		"Name":             name,
		"IsCustom":         true,
		"Description":      "Least-privilege read access for Nubicustos Azure scanning.",
		"Actions":          actions,
		"NotActions":       []string{},
		"DataActions":      []string{},
		"NotDataActions":   []string{},
		"AssignableScopes": []string{scope},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
