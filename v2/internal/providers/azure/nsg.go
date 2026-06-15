package azure

import (
	"errors"
	"fmt"

	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(nsgCollector{}) }

type nsgCollector struct{}

func (nsgCollector) Name() string { return "azure:nsg" }

// Collect gathers network-security-group inbound rules across the in-scope
// subscriptions so the checks can flag rules open to the internet.
func (nsgCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armnetwork.NewSecurityGroupsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure nsg: building client for subscription %s: %w", sub, err))
			continue
		}
		pager := client.NewListAllPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure nsg: listing security groups in subscription %s: %w", sub, err))
				break
			}
			for _, g := range page.Value {
				if g == nil {
					continue
				}
				nsg := state.NetworkSecurityGroup{
					ID:            str(g.ID),
					Name:          str(g.Name),
					ResourceGroup: resourceGroupFromID(str(g.ID)),
					Subscription:  sub,
					Location:      str(g.Location),
				}
				if g.Properties != nil {
					for _, r := range g.Properties.SecurityRules {
						nsg.Rules = append(nsg.Rules, normalizeRule(r))
					}
				}
				st.AddNSG(nsg)
			}
		}
	}
	return errors.Join(errs...)
}

// normalizeRule flattens an Azure security rule into the state model, resolving
// the source prefix from either the single-prefix or the list form.
func normalizeRule(r *armnetwork.SecurityRule) state.NSGRule {
	out := state.NSGRule{Name: str(r.Name)}
	p := r.Properties
	if p == nil {
		return out
	}
	if p.Direction != nil {
		out.Direction = string(*p.Direction)
	}
	if p.Access != nil {
		out.Access = string(*p.Access)
	}
	if p.Protocol != nil {
		out.Protocol = string(*p.Protocol)
	}
	out.Priority = int32Val(p.Priority)
	out.DestPorts = collect(str(p.DestinationPortRange), p.DestinationPortRanges)
	out.Sources = collect(str(p.SourceAddressPrefix), p.SourceAddressPrefixes)
	return out
}

// collect merges the single-value form and the list form of an NSG field into
// one slice — Azure populates exactly one of the two — preserving every entry so
// no port or source prefix is dropped.
func collect(single string, list []*string) []string {
	var out []string
	if single != "" {
		out = append(out, single)
	}
	for _, p := range list {
		if s := str(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
