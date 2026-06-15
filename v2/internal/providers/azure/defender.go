package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(defenderCollector{}) }

type defenderCollector struct{}

func (defenderCollector) Name() string { return "azure:defender" }

// Collect gathers Microsoft Defender for Cloud pricing tiers per subscription, so
// the check can flag resource-type plans left on the Free tier (no advanced
// threat protection).
func (defenderCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	client, err := armsecurity.NewPricingsClient(sc.Azure.Credential, nil)
	if err != nil {
		return fmt.Errorf("azure defender: building client: %w", err)
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		resp, err := client.List(sc.Ctx, "subscriptions/"+sub, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure defender: listing pricings in subscription %s: %w", sub, err))
			continue
		}
		for _, p := range resp.Value {
			if p == nil || p.Properties == nil || p.Properties.PricingTier == nil {
				continue
			}
			st.AddDefenderPlan(state.DefenderPlan{
				Subscription: sub,
				Name:         str(p.Name),
				Tier:         string(*p.Properties.PricingTier),
			})
		}
	}
	return errors.Join(errs...)
}
