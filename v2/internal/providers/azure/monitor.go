package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(monitorCollector{}) }

type monitorCollector struct{}

func (monitorCollector) Name() string { return "azure:monitor" }

// Collect gathers per-subscription monitoring posture (CIS Azure section 5.2):
// which sensitive operations have an enabled activity-log alert. A read failure
// is recorded so the check judges only what was actually collected.
func (monitorCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		m := state.AzureMonitor{Subscription: sub}
		if ac, err := armmonitor.NewActivityLogAlertsClient(sub, sc.Azure.Credential, nil); err == nil {
			ops, readErr := alertedOperations(sc, ac)
			if readErr == nil {
				m.AlertsReadOK = true
				m.AlertedOperations = ops
			} else {
				errs = append(errs, fmt.Errorf("azure monitor: activity log alerts in %s: %w", sub, readErr))
			}
		}
		st.AddAzureMonitor(m)
	}
	return errors.Join(errs...)
}

// alertedOperations returns the operationName values covered by enabled activity-
// log alerts across the subscription.
func alertedOperations(sc *engine.ScanContext, client *armmonitor.ActivityLogAlertsClient) ([]string, error) {
	var ops []string
	pager := client.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return nil, err
		}
		for _, alert := range page.Value {
			if alert == nil || alert.Properties == nil {
				continue
			}
			p := alert.Properties
			if p.Enabled != nil && !*p.Enabled {
				continue // a disabled alert provides no coverage
			}
			if p.Condition == nil {
				continue
			}
			for _, leaf := range p.Condition.AllOf {
				if leaf == nil || leaf.Field == nil || leaf.Equals == nil {
					continue
				}
				if *leaf.Field == "operationName" {
					ops = append(ops, *leaf.Equals)
				}
			}
		}
	}
	return ops, nil
}
