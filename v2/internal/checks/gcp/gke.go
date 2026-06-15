package gcp

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(gkeLegacyABAC{})
	engine.RegisterCheck(gkeNetworkPolicyDisabled{})
	engine.RegisterCheck(gkeMasterNetworksOpen{})
}

func gkeResource(c state.GKECluster) findings.Resource {
	return findings.Resource{
		ID: c.Name, Name: c.Name, Type: "gcp_gke_cluster", Provider: "gcp",
		Account: c.Project, Region: c.Location,
	}
}

type gkeLegacyABAC struct{}

func (gkeLegacyABAC) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_gke_legacy_abac_enabled", Title: "GKE cluster has legacy ABAC authorization enabled",
		Provider: "gcp", Service: "gke", Severity: findings.SeverityHigh,
		Rationale:   "Legacy ABAC grants broad, static authorization that bypasses the least-privilege controls of Kubernetes RBAC, often giving workloads far more access than intended.",
		Impact:      "A compromised pod or token inherits the over-broad ABAC permissions, easing cluster-wide lateral movement.",
		Remediation: "Disable legacy ABAC (RBAC remains): gcloud container clusters update <name> --no-enable-legacy-authorization",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "7.16"}},
	}
}

func (c gkeLegacyABAC) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cl := range st.GCP.GKEClusters {
		if !cl.LegacyABAC {
			continue
		}
		desc := fmt.Sprintf("GKE cluster %q (project %s) has legacy ABAC authorization enabled.", cl.Name, cl.Project)
		poc := fmt.Sprintf("gcloud container clusters describe %s --location %s --project %s --format='value(legacyAbac.enabled)'", cl.Name, cl.Location, cl.Project)
		out = append(out, findings.New(c.Spec(), gkeResource(cl), desc, poc, now))
	}
	return out, nil
}

type gkeNetworkPolicyDisabled struct{}

func (gkeNetworkPolicyDisabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_gke_network_policy_disabled", Title: "GKE cluster does not enforce network policy",
		Provider: "gcp", Service: "gke", Severity: findings.SeverityMedium,
		Rationale:   "Without network policy enforcement, every pod can reach every other pod, so a single compromised workload can pivot freely across the cluster.",
		Impact:      "Lateral movement between pods is unrestricted after an initial foothold.",
		Remediation: "Enable network policy: gcloud container clusters update <name> --enable-network-policy",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "7.14"}},
	}
}

func (c gkeNetworkPolicyDisabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cl := range st.GCP.GKEClusters {
		if cl.NetworkPolicyEnabled {
			continue
		}
		desc := fmt.Sprintf("GKE cluster %q does not enforce pod network policy.", cl.Name)
		poc := fmt.Sprintf("gcloud container clusters describe %s --location %s --project %s --format='value(networkPolicy.enabled)'", cl.Name, cl.Location, cl.Project)
		out = append(out, findings.New(c.Spec(), gkeResource(cl), desc, poc, now))
	}
	return out, nil
}

type gkeMasterNetworksOpen struct{}

func (gkeMasterNetworksOpen) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_gke_master_authorized_networks_disabled", Title: "GKE control plane is not restricted to authorized networks",
		Provider: "gcp", Service: "gke", Severity: findings.SeverityMedium,
		Rationale:   "With master authorized networks disabled, the cluster's control-plane endpoint accepts connections from any source IP, exposing the Kubernetes API to the internet.",
		Impact:      "The API server is reachable from anywhere, broadening the surface for credential and exploit attacks against the control plane.",
		Remediation: "Restrict control-plane access: gcloud container clusters update <name> --enable-master-authorized-networks --master-authorized-networks=<cidr>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "7.7"}},
	}
}

func (c gkeMasterNetworksOpen) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cl := range st.GCP.GKEClusters {
		if cl.MasterAuthorizedNetworks {
			continue
		}
		desc := fmt.Sprintf("GKE cluster %q does not restrict control-plane access to authorized networks.", cl.Name)
		poc := fmt.Sprintf("gcloud container clusters describe %s --location %s --project %s --format='value(masterAuthorizedNetworksConfig.enabled)'", cl.Name, cl.Location, cl.Project)
		out = append(out, findings.New(c.Spec(), gkeResource(cl), desc, poc, now))
	}
	return out, nil
}
