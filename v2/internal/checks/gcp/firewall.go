package gcp

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

func init() { engine.RegisterCheck(firewallOpenIngress{}) }

type firewallOpenIngress struct{}

func (firewallOpenIngress) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_firewall_open_ingress", Title: "Firewall rule exposes sensitive ports to the internet",
		Provider: "gcp", Service: "compute", Severity: findings.SeverityHigh,
		Rationale:   "An enabled ingress firewall rule with source range 0.0.0.0/0 on an administrative or database port is reachable by any host on the internet.",
		Impact:      "Attackers can brute-force or directly attack the exposed service without a prior foothold.",
		Remediation: "Restrict the rule's source ranges to trusted CIDRs: gcloud compute firewall-rules update <name> --source-ranges <cidr>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "3.6"}},
	}
}

func (c firewallOpenIngress) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, fw := range st.GCP.Firewalls {
		labels := exposedSensitive(fw)
		if len(labels) == 0 {
			continue
		}
		res := findings.Resource{
			ID: fw.Name, Name: fw.Name, Type: "gcp_compute_firewall", Provider: "gcp", Account: fw.Project,
		}
		desc := fmt.Sprintf("Firewall %q (network %s) exposes %s to the internet.", fw.Name, fw.Network, strings.Join(labels, ", "))
		poc := fmt.Sprintf("gcloud compute firewall-rules describe %s --project %s", fw.Name, fw.Project)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

// exposedSensitive returns labels for the sensitive ports a firewall rule opens
// to the internet (enabled INGRESS Allow from 0.0.0.0/0).
func exposedSensitive(fw state.FirewallRule) []string {
	if fw.Disabled || !strings.EqualFold(fw.Direction, "INGRESS") || !openToInternet(fw.SourceRanges) {
		return nil
	}
	set := map[string]struct{}{}
	for _, spec := range fw.Allowed {
		proto, ports, hasPorts := strings.Cut(spec, ":")
		if !hasPorts {
			// A bare protocol with no port restriction opens every port. Only
			// "all" and "tcp" reach the TCP services in the sensitive catalog;
			// a bare "udp" does not expose SSH/RDP/etc., so it is not flagged here.
			if proto == "all" || proto == "tcp" {
				set["all ports"] = struct{}{}
			}
			continue
		}
		// Ports only matter for TCP (and "all"); UDP-scoped ports don't reach the
		// TCP sensitive services.
		if !(proto == "tcp" || proto == "all") {
			continue
		}
		for _, pr := range strings.Split(ports, ",") {
			if portspec.IsAllPorts(pr) {
				set["all ports"] = struct{}{}
				continue
			}
			for port, label := range portspec.Sensitive {
				if portspec.Covers(port, pr) {
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

func openToInternet(ranges []string) bool {
	for _, r := range ranges {
		if r == "0.0.0.0/0" || r == "::/0" {
			return true
		}
	}
	return false
}
