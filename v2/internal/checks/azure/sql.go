package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(sqlPublicNetwork{})
	engine.RegisterCheck(sqlFirewallAllowAll{})
	engine.RegisterCheck(sqlMinTLS{})
}

// sqlResource builds the normalized resource for a SQL server.
func sqlResource(s state.SQLServer) findings.Resource {
	return findings.Resource{
		ID: s.Name, Name: s.Name, Type: "azure_sql_server", Provider: "azure",
		Account: s.Subscription, Region: s.Location,
	}
}

type sqlPublicNetwork struct{}

func (sqlPublicNetwork) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_sql_public_network_access", Title: "SQL server has public network access enabled",
		Provider: "azure", Service: "sql", Severity: findings.SeverityHigh,
		Rationale:   "A SQL server with public network access enabled is reachable from outside the virtual network, exposing the database endpoint to the internet (subject to firewall rules).",
		Impact:      "The database endpoint can be reached by external hosts, widening the attack surface for credential and injection attacks.",
		Remediation: "Disable the public endpoint and use a private endpoint: az sql server update --name <name> --resource-group <rg> --enable-public-network false",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.1.2"}},
	}
}

func (c sqlPublicNetwork) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, s := range st.Azure.SQLServers {
		if !s.PublicNetworkAccess {
			continue
		}
		desc := fmt.Sprintf("SQL server %q (sub %s) has public network access enabled.", s.Name, s.Subscription)
		poc := fmt.Sprintf("az sql server show --name %s --resource-group %s --query publicNetworkAccess", s.Name, s.ResourceGroup)
		out = append(out, findings.New(c.Spec(), sqlResource(s), desc, poc, now))
	}
	return out, nil
}

type sqlFirewallAllowAll struct{}

func (sqlFirewallAllowAll) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_sql_firewall_allow_all", Title: "SQL server firewall allows the entire internet",
		Provider: "azure", Service: "sql", Severity: findings.SeverityHigh,
		Rationale:   "A firewall rule spanning 0.0.0.0 to 255.255.255.255 permits connections from every host on the internet, defeating the server-level firewall.",
		Impact:      "Any host online can attempt to authenticate to the database, enabling brute-force and direct exploitation.",
		Remediation: "Remove the open rule and scope to required addresses: az sql server firewall-rule delete --name <rule> --server <name> --resource-group <rg>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.1.1"}},
	}
}

func (c sqlFirewallAllowAll) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, s := range st.Azure.SQLServers {
		var open []string
		for _, r := range s.FirewallRules {
			if r.OpensToInternet() {
				open = append(open, r.Name)
			}
		}
		if len(open) == 0 {
			continue
		}
		desc := fmt.Sprintf("SQL server %q has firewall rule(s) open to the entire internet: %v.", s.Name, open)
		poc := fmt.Sprintf("az sql server firewall-rule list --server %s --resource-group %s -o table", s.Name, s.ResourceGroup)
		out = append(out, findings.New(c.Spec(), sqlResource(s), desc, poc, now))
	}
	return out, nil
}

type sqlMinTLS struct{}

func (sqlMinTLS) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_sql_min_tls", Title: "SQL server allows TLS below 1.2",
		Provider: "azure", Service: "sql", Severity: findings.SeverityMedium,
		Rationale:   "A minimal TLS version below 1.2 (including None) lets clients connect with deprecated, weak TLS or no enforced minimum at all.",
		Impact:      "Database connections can be negotiated down to weak TLS, exposing credentials and query data in transit.",
		Remediation: "az sql server update --name <name> --resource-group <rg> --minimal-tls-version 1.2",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.1.8"}},
	}
}

func (c sqlMinTLS) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, s := range st.Azure.SQLServers {
		// Empty means undeterminable; only flag a version explicitly below 1.2.
		if s.MinTLSVersion == "" || s.MinTLSVersion == "1.2" {
			continue
		}
		desc := fmt.Sprintf("SQL server %q sets a minimum TLS version of %q (below 1.2).", s.Name, s.MinTLSVersion)
		poc := fmt.Sprintf("az sql server show --name %s --resource-group %s --query minimalTlsVersion", s.Name, s.ResourceGroup)
		out = append(out, findings.New(c.Spec(), sqlResource(s), desc, poc, now))
	}
	return out, nil
}
