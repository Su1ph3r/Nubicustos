package azure

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(storageCollector{}) }

type storageCollector struct{}

func (storageCollector) Name() string { return "azure:storage" }

// Collect gathers storage-account posture across the in-scope subscriptions:
// anonymous blob access, HTTPS enforcement, minimum TLS, and the network rule
// default action.
func (storageCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armstorage.NewAccountsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			continue
		}
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, acct := range page.Value {
				if acct == nil {
					continue
				}
				sa := state.StorageAccount{
					Name:          str(acct.Name),
					ResourceGroup: resourceGroupFromID(str(acct.ID)),
					Subscription:  sub,
					Location:      str(acct.Location),
				}
				if p := acct.Properties; p != nil {
					sa.AllowBlobPublicAccess = boolVal(p.AllowBlobPublicAccess)
					sa.HTTPSOnly = boolVal(p.EnableHTTPSTrafficOnly)
					if p.MinimumTLSVersion != nil {
						sa.MinTLSVersion = string(*p.MinimumTLSVersion)
					}
					if nrs := p.NetworkRuleSet; nrs != nil && nrs.DefaultAction != nil {
						sa.NetworkDefaultAllow = *nrs.DefaultAction == armstorage.DefaultActionAllow
					}
				}
				st.AddStorageAccount(sa)
			}
		}
	}
	return nil
}
