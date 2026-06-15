package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(rbacCustomRoleWildcard{}) }

type rbacCustomRoleWildcard struct{}

func (rbacCustomRoleWildcard) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_rbac_custom_role_wildcard", Title: "Custom RBAC role grants a wildcard action",
		Provider: "azure", Service: "rbac", Severity: findings.SeverityHigh,
		Rationale:   "A custom role whose permissions include the \"*\" action grants every control-plane operation, equivalent to Owner. Assigning it broadens privilege far beyond intent and is a ready privilege-escalation path.",
		Impact:      "Any principal assigned the role can perform any management action in its scope, including granting itself further access.",
		Remediation: "Replace the wildcard with the specific actions the role needs: az role definition update --role-definition <scoped-definition.json>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "1.23"}},
	}
}

func (c rbacCustomRoleWildcard) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, r := range st.Azure.CustomRoles {
		if !r.WildcardAction {
			continue
		}
		res := findings.Resource{
			ID: r.Name, Name: r.Name, Type: "azure_custom_role", Provider: "azure", Account: r.Subscription,
		}
		desc := fmt.Sprintf("Custom RBAC role %q (sub %s) grants the wildcard \"*\" action.", r.Name, r.Subscription)
		poc := fmt.Sprintf("az role definition list --custom-role-only true --query \"[?roleName=='%s'].permissions\"", r.Name)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
