package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// EnabledSubscriptions enumerates the subscriptions the credential can see and
// returns the ids of the enabled ones (plan §9.4 — Azure discovery). It is used
// up front, off the validated credential, so the scan fans out across the whole
// estate without re-prompting.
func EnabledSubscriptions(ctx context.Context, cred azcore.TokenCredential) ([]string, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, err
	}
	var out []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, s := range page.Value {
			if s == nil || s.SubscriptionID == nil {
				continue
			}
			if s.State != nil && *s.State != armsubscriptions.SubscriptionStateEnabled {
				continue // skip disabled/warned/deleted subscriptions
			}
			out = append(out, *s.SubscriptionID)
		}
	}
	return out, nil
}
