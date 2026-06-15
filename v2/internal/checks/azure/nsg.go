package azure

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/portspec"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(nsgOpenIngress{}) }

type nsgOpenIngress struct{}

func (nsgOpenIngress) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_nsg_open_ingress", Title: "Network security group exposes sensitive ports to the internet",
		Provider: "azure", Service: "network", Severity: findings.SeverityHigh,
		Rationale:   "An inbound Allow rule from the internet (source *, Internet, or 0.0.0.0/0) on an administrative or database port is directly reachable by any host online.",
		Impact:      "Attackers can brute-force or directly attack the exposed service without a prior foothold.",
		Remediation: "Restrict the rule's source to specific address prefixes or remove it: az network nsg rule update --nsg-name <nsg> --resource-group <rg> --name <rule> --source-address-prefixes <cidr>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "6.1"}},
	}
}

func (c nsgOpenIngress) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, nsg := range st.Azure.NSGs {
		labels := exposedSensitive(nsg)
		if len(labels) == 0 {
			continue
		}
		res := findings.Resource{
			ID: nsg.Name, Name: nsg.Name, Type: "azure_network_security_group", Provider: "azure",
			Account: nsg.Subscription, Region: nsg.Location,
		}
		desc := fmt.Sprintf("NSG %q exposes %s to the internet.", nsg.Name, strings.Join(labels, ", "))
		poc := fmt.Sprintf("az network nsg rule list --nsg-name %s --resource-group %s -o table", nsg.Name, nsg.ResourceGroup)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

// exposedSensitive returns the labels for sensitive ports an NSG exposes to the
// internet via an inbound Allow rule. Each rule may carry several destination
// port specs (single values and ranges); every one is evaluated.
func exposedSensitive(nsg state.NetworkSecurityGroup) []string {
	set := map[string]struct{}{}
	for _, r := range nsg.Rules {
		if !r.OpenToInternet() {
			continue
		}
		for _, spec := range r.DestPorts {
			if portspec.IsAllPorts(spec) {
				set["all ports"] = struct{}{}
				continue
			}
			for port, label := range portspec.Sensitive {
				if portspec.Covers(port, spec) {
					set[fmt.Sprintf("%s (%d)", label, port)] = struct{}{}
				}
			}
		}
	}
	labels := make([]string, 0, len(set))
	for l := range set {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	return labels
}
