package azure

import (
	"errors"
	"fmt"

	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	armredis "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v3"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCollector(vmCollector{})
	engine.RegisterCollector(redisCollector{})
}

type vmCollector struct{}

func (vmCollector) Name() string { return "azure:vm" }

// Collect gathers virtual-machine posture across the in-scope subscriptions:
// whether encryption at host is enabled. Per-subscription failures are tolerated.
func (vmCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armcompute.NewVirtualMachinesClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure vm: client for %s: %w", sub, err))
			continue
		}
		pager := client.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure vm: listing VMs in %s: %w", sub, err))
				break
			}
			for _, vm := range page.Value {
				if vm == nil {
					continue
				}
				v := state.AzureVM{
					Name: str(vm.Name), ResourceGroup: resourceGroupFromID(str(vm.ID)),
					Subscription: sub, Location: str(vm.Location),
				}
				if p := vm.Properties; p != nil && p.SecurityProfile != nil {
					v.EncryptionAtHost = p.SecurityProfile.EncryptionAtHost != nil && *p.SecurityProfile.EncryptionAtHost
				}
				st.AddAzureVM(v)
			}
		}
	}
	return errors.Join(errs...)
}

type redisCollector struct{}

func (redisCollector) Name() string { return "azure:redis" }

// Collect gathers Azure Cache for Redis posture: whether the non-TLS port is
// enabled. Per-subscription failures are tolerated.
func (redisCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armredis.NewClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure redis: client for %s: %w", sub, err))
			continue
		}
		pager := client.NewListBySubscriptionPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure redis: listing caches in %s: %w", sub, err))
				break
			}
			for _, r := range page.Value {
				if r == nil {
					continue
				}
				cache := state.AzureRedis{
					Name: str(r.Name), ResourceGroup: resourceGroupFromID(str(r.ID)),
					Subscription: sub, Location: str(r.Location),
				}
				if p := r.Properties; p != nil {
					cache.NonSSLPortEnabled = p.EnableNonSSLPort != nil && *p.EnableNonSSLPort
				}
				st.AddAzureRedis(cache)
			}
		}
	}
	return errors.Join(errs...)
}
