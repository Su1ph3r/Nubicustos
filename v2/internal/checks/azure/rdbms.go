package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(dbFlexPublicNetwork{}) }

type dbFlexPublicNetwork struct{}

func (dbFlexPublicNetwork) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_db_flexible_public_network_access", Title: "Azure Database flexible server has public network access enabled",
		Provider: "azure", Service: "rdbms", Severity: findings.SeverityHigh,
		Rationale:   "A MySQL/PostgreSQL flexible server with public network access enabled is reachable from outside the virtual network, exposing the database endpoint to the internet (subject to firewall rules).",
		Impact:      "The database endpoint can be reached by external hosts, widening the attack surface for credential and injection attacks.",
		Remediation: "Disable public access and use private access / VNet integration: az <mysql|postgres> flexible-server update --name <name> --resource-group <rg> --public-access Disabled",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.x"}},
	}
}

func (c dbFlexPublicNetwork) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, d := range st.Azure.DBFlexServers {
		if !d.PublicNetworkAccess {
			continue
		}
		res := findings.Resource{
			ID: d.Name, Name: d.Name, Type: "azure_" + d.Engine + "_flexible_server", Provider: "azure",
			Account: d.Subscription, Region: d.Location,
		}
		desc := fmt.Sprintf("Azure %s flexible server %q (sub %s) has public network access enabled.", d.Engine, d.Name, d.Subscription)
		poc := fmt.Sprintf("az %s flexible-server show --name %s --resource-group %s --query network.publicNetworkAccess", dbCLIName(d.Engine), d.Name, d.ResourceGroup)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

func dbCLIName(engine string) string {
	if engine == "postgresql" {
		return "postgres"
	}
	return engine
}
