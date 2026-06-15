package azure

import (
	"errors"
	"fmt"

	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(networkCollector{}) }

type networkCollector struct{}

func (networkCollector) Name() string { return "azure:network" }

// Collect gathers the network topology the reachability solver needs (§9.5):
// network interfaces (public-IP and NSG association) and subnet→NSG bindings, so
// an NSG open to the internet can be told apart from one that governs only
// private NICs. Per-subscription failures are tolerated.
func (networkCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		if err := collectNICs(sc, st, sub); err != nil {
			errs = append(errs, err)
		}
		if err := collectSubnetNSGs(sc, st, sub); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func collectNICs(sc *engine.ScanContext, st *state.State, sub string) error {
	client, err := armnetwork.NewInterfacesClient(sub, sc.Azure.Credential, nil)
	if err != nil {
		return fmt.Errorf("azure network: building interfaces client for subscription %s: %w", sub, err)
	}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return fmt.Errorf("azure network: listing interfaces in subscription %s: %w", sub, err)
		}
		for _, nic := range page.Value {
			if nic == nil || nic.Properties == nil {
				continue
			}
			n := state.AzureNIC{Name: str(nic.Name)}
			if nsg := nic.Properties.NetworkSecurityGroup; nsg != nil {
				n.NSGID = str(nsg.ID)
			}
			for _, ipc := range nic.Properties.IPConfigurations {
				if ipc == nil || ipc.Properties == nil {
					continue
				}
				if ipc.Properties.PublicIPAddress != nil {
					n.HasPublicIP = true
				}
				if sn := ipc.Properties.Subnet; sn != nil && n.SubnetID == "" {
					n.SubnetID = str(sn.ID)
				}
			}
			st.AddAzureNIC(n)
		}
	}
	return nil
}

func collectSubnetNSGs(sc *engine.ScanContext, st *state.State, sub string) error {
	client, err := armnetwork.NewVirtualNetworksClient(sub, sc.Azure.Credential, nil)
	if err != nil {
		return fmt.Errorf("azure network: building vnets client for subscription %s: %w", sub, err)
	}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return fmt.Errorf("azure network: listing vnets in subscription %s: %w", sub, err)
		}
		for _, vnet := range page.Value {
			if vnet == nil || vnet.Properties == nil {
				continue
			}
			for _, sn := range vnet.Properties.Subnets {
				if sn == nil || sn.Properties == nil || sn.Properties.NetworkSecurityGroup == nil {
					continue
				}
				st.AddAzureSubnetNSG(state.AzureSubnetNSG{
					SubnetID: str(sn.ID),
					NSGID:    str(sn.Properties.NetworkSecurityGroup.ID),
				})
			}
		}
	}
	return nil
}
