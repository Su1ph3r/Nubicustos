package reachability

import (
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// AzureResult holds the precomputed NSG→public-exposure index for Azure
// reachability queries (§9.5). An NSG open to the internet is only genuinely
// exposed if it governs at least one NIC that has a public IP; one bound only to
// private NICs is "open on paper but unreachable".
type AzureResult struct {
	nsgHasPublicNIC map[string]bool // NSG id -> governs >=1 NIC with a public IP
	nsgGoverns      map[string]bool // NSG id -> governs >=1 NIC at all
	verdictByName   map[string]findings.Reachability
	hasTopology     bool // any NIC data collected
}

// SolveAzure indexes NIC and subnet topology so each NSG's internet
// exposure can be judged. Pure and nil-safe.
func SolveAzure(a *state.Azure) *AzureResult {
	r := &AzureResult{
		nsgHasPublicNIC: map[string]bool{},
		nsgGoverns:      map[string]bool{},
		verdictByName:   map[string]findings.Reachability{},
	}
	if a == nil {
		return r
	}
	// subnet id -> NSG id (subnet-level NSGs apply to every NIC in the subnet).
	subnetNSG := make(map[string]string, len(a.SubnetNSGs))
	for _, s := range a.SubnetNSGs {
		subnetNSG[s.SubnetID] = s.NSGID
	}

	r.hasTopology = len(a.NICs) > 0
	for _, nic := range a.NICs {
		for _, nsgID := range effectiveNSGs(nic, subnetNSG) {
			r.nsgGoverns[nsgID] = true
			if nic.HasPublicIP {
				r.nsgHasPublicNIC[nsgID] = true
			}
		}
	}

	// Precompute a per-NSG verdict keyed by name for annotation (the NSG finding
	// is scoped by NSG name).
	for _, nsg := range a.NSGs {
		r.verdictByName[nsg.Name] = r.nsgVerdict(nsg.ID)
	}
	return r
}

// effectiveNSGs returns the NSG ids that govern a NIC: its own NIC-level NSG plus
// its subnet's NSG.
func effectiveNSGs(nic state.AzureNIC, subnetNSG map[string]string) []string {
	var out []string
	if nic.NSGID != "" {
		out = append(out, nic.NSGID)
	}
	if sn := subnetNSG[nic.SubnetID]; sn != "" {
		out = append(out, sn)
	}
	return out
}

// nsgVerdict classifies an NSG's internet exposure by id.
func (r *AzureResult) nsgVerdict(nsgID string) findings.Reachability {
	switch {
	case !r.hasTopology || nsgID == "":
		return findings.ReachUnknown // no NIC topology collected, or NSG id unknown
	case r.nsgHasPublicNIC[nsgID]:
		return findings.ReachYes
	case r.nsgGoverns[nsgID]:
		return findings.ReachNo // governs NICs, but none have a public IP
	default:
		return findings.ReachUnknown // not associated with any collected NIC/subnet
	}
}

// AnnotateAzure sets the Reachable field on Azure NSG open-ingress findings from
// the topology. Conservative: it annotates only the NSG open-ingress finding
// (scoped by NSG name) and leaves others at their default (unknown).
func AnnotateAzure(fs []findings.Finding, a *state.Azure, r *AzureResult) {
	if a == nil || r == nil {
		return
	}
	for i := range fs {
		if fs[i].CheckID != "azure_nsg_open_ingress" {
			continue
		}
		if v, ok := r.verdictByName[fs[i].Resource.Name]; ok {
			fs[i].Reachable = v
		}
	}
}
