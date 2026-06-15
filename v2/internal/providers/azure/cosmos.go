package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(cosmosCollector{}) }

type cosmosCollector struct{}

func (cosmosCollector) Name() string { return "azure:cosmos" }

// Collect gathers Cosmos DB account posture across the in-scope subscriptions:
// public network access and whether key-based (local) authorization is disabled.
func (cosmosCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armcosmos.NewDatabaseAccountsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure cosmos: building client for subscription %s: %w", sub, err))
			continue
		}
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure cosmos: listing accounts in subscription %s: %w", sub, err))
				break
			}
			for _, acct := range page.Value {
				if acct == nil {
					continue
				}
				a := state.CosmosAccount{
					Name:          str(acct.Name),
					ResourceGroup: resourceGroupFromID(str(acct.ID)),
					Subscription:  sub,
					Location:      str(acct.Location),
				}
				if p := acct.Properties; p != nil {
					// PublicNetworkAccess defaults to Enabled when unset.
					a.PublicNetworkAccess = p.PublicNetworkAccess == nil ||
						*p.PublicNetworkAccess == armcosmos.PublicNetworkAccessEnabled
					a.LocalAuthDisabled = p.DisableLocalAuth != nil && *p.DisableLocalAuth
				}
				st.AddCosmosAccount(a)
			}
		}
	}
	return errors.Join(errs...)
}
