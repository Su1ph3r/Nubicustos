package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(storageCollector{}) }

type storageCollector struct{}

func (storageCollector) Name() string { return "azure:storage" }

// Collect gathers storage-account posture across the in-scope subscriptions:
// anonymous blob access, HTTPS enforcement, minimum TLS, shared-key (account-key)
// auth, and the network rule default action.
func (storageCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armstorage.NewAccountsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure storage: building client for subscription %s: %w", sub, err))
			continue
		}
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure storage: listing accounts in subscription %s: %w", sub, err))
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
					// Azure leaves AllowSharedKeyAccess nil when never configured, and
					// the platform default is to permit shared-key auth — so nil and
					// explicit true both mean "allowed".
					sa.SharedKeyAccessAllowed = p.AllowSharedKeyAccess == nil || *p.AllowSharedKeyAccess
				}
				st.AddStorageAccount(sa)
			}
		}
	}
	return errors.Join(errs...)
}
