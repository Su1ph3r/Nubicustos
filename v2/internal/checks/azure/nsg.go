package azure

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(nsgOpenIngress{}) }

// sensitivePorts maps high-risk ports exposed inbound to the internet to a label.
var sensitivePorts = map[int]string{
	22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP", 3306: "MySQL",
	5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 1433: "MSSQL", 9200: "Elasticsearch",
}

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
// internet via an inbound Allow rule.
func exposedSensitive(nsg state.NetworkSecurityGroup) []string {
	set := map[string]struct{}{}
	for _, r := range nsg.Rules {
		if !r.OpenToInternet() {
			continue
		}
		if r.DestPorts == "*" || r.DestPorts == "0-65535" {
			set["all ports"] = struct{}{}
			continue
		}
		for port, label := range sensitivePorts {
			if portInRange(port, r.DestPorts) {
				set[fmt.Sprintf("%s (%d)", label, port)] = struct{}{}
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

// portInRange reports whether port is covered by an Azure port spec ("22" or
// "20-30"). Comma-separated lists arrive as separate rules/specs in practice;
// the single-value and range forms are handled here.
func portInRange(port int, spec string) bool {
	if spec == "" {
		return false
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		return err1 == nil && err2 == nil && port >= l && port <= h
	}
	p, err := strconv.Atoi(strings.TrimSpace(spec))
	return err == nil && p == port
}
