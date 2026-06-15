package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(keyVaultCollector{}) }

type keyVaultCollector struct{}

func (keyVaultCollector) Name() string { return "azure:keyvault" }

// Collect gathers key-vault posture across the in-scope subscriptions:
// soft-delete, purge protection, and the network ACL default action.
func (keyVaultCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armkeyvault.NewVaultsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure keyvault: building client for subscription %s: %w", sub, err))
			continue
		}
		pager := client.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure keyvault: listing vaults in subscription %s: %w", sub, err))
				break
			}
			for _, v := range page.Value {
				if v == nil {
					continue
				}
				kv := state.KeyVault{
					Name:          str(v.Name),
					ResourceGroup: resourceGroupFromID(str(v.ID)),
					Subscription:  sub,
					Location:      str(v.Location),
				}
				if p := v.Properties; p != nil {
					kv.SoftDeleteEnabled = boolVal(p.EnableSoftDelete)
					kv.PurgeProtection = boolVal(p.EnablePurgeProtection)
					if acl := p.NetworkACLs; acl != nil && acl.DefaultAction != nil {
						kv.NetworkDefaultAllow = *acl.DefaultAction == armkeyvault.NetworkRuleActionAllow
					}
				}
				st.AddKeyVault(kv)
			}
		}
	}
	return errors.Join(errs...)
}
