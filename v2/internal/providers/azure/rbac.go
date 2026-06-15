package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(rbacCollector{}) }

type rbacCollector struct{}

func (rbacCollector) Name() string { return "azure:rbac" }

// Collect gathers custom RBAC role definitions across the in-scope subscriptions
// and records whether each grants a wildcard control-plane action — the trust
// surface where over-broad custom roles enable privilege escalation.
func (rbacCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	client, err := armauthorization.NewRoleDefinitionsClient(sc.Azure.Credential, nil)
	if err != nil {
		return fmt.Errorf("azure rbac: building client: %w", err)
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		scope := "/subscriptions/" + sub
		pager := client.NewListPager(scope, nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure rbac: listing role definitions in subscription %s: %w", sub, err))
				break
			}
			for _, def := range page.Value {
				if def == nil || def.Properties == nil {
					continue
				}
				p := def.Properties
				// Only custom roles are actionable; built-in roles are fixed by Azure.
				if p.RoleType == nil || *p.RoleType != "CustomRole" {
					continue
				}
				st.AddAzureCustomRole(state.AzureCustomRole{
					Name:           strOr(p.RoleName, str(def.Name)),
					Subscription:   sub,
					WildcardAction: permissionsHaveWildcard(p.Permissions),
				})
			}
		}
	}
	return errors.Join(errs...)
}

// permissionsHaveWildcard reports whether any permission grants the "*" action.
func permissionsHaveWildcard(perms []*armauthorization.Permission) bool {
	for _, perm := range perms {
		if perm == nil {
			continue
		}
		for _, a := range perm.Actions {
			if a != nil && *a == "*" {
				return true
			}
		}
	}
	return false
}

// strOr returns *p if non-nil and non-empty, else fallback.
func strOr(p *string, fallback string) string {
	if p != nil && *p != "" {
		return *p
	}
	return fallback
}
