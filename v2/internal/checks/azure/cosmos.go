package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(cosmosPublicNetwork{})
	engine.RegisterCheck(cosmosLocalAuth{})
}

func cosmosResource(a state.CosmosAccount) findings.Resource {
	return findings.Resource{
		ID: a.Name, Name: a.Name, Type: "azure_cosmosdb_account", Provider: "azure",
		Account: a.Subscription, Region: a.Location,
	}
}

type cosmosPublicNetwork struct{}

func (cosmosPublicNetwork) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_cosmosdb_public_network_access", Title: "Cosmos DB account has public network access enabled",
		Provider: "azure", Service: "cosmosdb", Severity: findings.SeverityHigh,
		Rationale:   "A Cosmos DB account with public network access enabled is reachable from outside the virtual network, exposing the data-plane endpoint to the internet (subject to firewall rules).",
		Impact:      "The account endpoint can be reached by external hosts, widening the attack surface for key-theft and data-access attacks.",
		Remediation: "Disable public access and use private endpoints: az cosmosdb update --name <name> --resource-group <rg> --public-network-access DISABLED",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.5"}},
	}
}

func (c cosmosPublicNetwork) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.CosmosAccounts {
		if !a.PublicNetworkAccess {
			continue
		}
		desc := fmt.Sprintf("Cosmos DB account %q (sub %s) has public network access enabled.", a.Name, a.Subscription)
		poc := fmt.Sprintf("az cosmosdb show --name %s --resource-group %s --query publicNetworkAccess", a.Name, a.ResourceGroup)
		out = append(out, findings.New(c.Spec(), cosmosResource(a), desc, poc, now))
	}
	return out, nil
}

type cosmosLocalAuth struct{}

func (cosmosLocalAuth) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_cosmosdb_local_auth_enabled", Title: "Cosmos DB account permits key-based (local) authorization",
		Provider: "azure", Service: "cosmosdb", Severity: findings.SeverityMedium,
		Rationale:   "With local auth enabled, anyone holding an account key has full data-plane access, bypassing Entra ID identity, RBAC, and conditional access; a leaked key is unattributable and grants complete access.",
		Impact:      "A leaked Cosmos DB key grants full, unattributable read/write to all data in the account.",
		Remediation: "Disable key-based auth and require Entra ID: az resource update --ids <accountId> --set properties.disableLocalAuth=true",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.6"}},
	}
}

func (c cosmosLocalAuth) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.CosmosAccounts {
		if a.LocalAuthDisabled {
			continue
		}
		desc := fmt.Sprintf("Cosmos DB account %q permits key-based (local) authorization.", a.Name)
		poc := fmt.Sprintf("az resource show --ids <accountId> --query properties.disableLocalAuth  # %s", a.Name)
		out = append(out, findings.New(c.Spec(), cosmosResource(a), desc, poc, now))
	}
	return out, nil
}
