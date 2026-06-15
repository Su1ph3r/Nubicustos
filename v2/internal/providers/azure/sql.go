package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(sqlCollector{}) }

// sqlCollector gathers Azure SQL logical-server posture across the in-scope
// subscriptions: public network access, minimum TLS version, and the server's
// firewall rules (used to detect rules open to the whole internet). Per-
// subscription and per-server failures are tolerated so one inaccessible server
// never blanks the rest.
type sqlCollector struct{}

func (sqlCollector) Name() string { return "azure:sql" }

func (sqlCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		servers, err := armsql.NewServersClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure sql: building servers client for subscription %s: %w", sub, err))
			continue
		}
		fwClient, err := armsql.NewFirewallRulesClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure sql: building firewall client for subscription %s: %w", sub, err))
			continue
		}
		pager := servers.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure sql: listing servers in subscription %s: %w", sub, err))
				break
			}
			for _, srv := range page.Value {
				if srv == nil {
					continue
				}
				name := str(srv.Name)
				rg := resourceGroupFromID(str(srv.ID))
				if name == "" || rg == "" {
					continue
				}
				s := state.SQLServer{
					Name:          name,
					ResourceGroup: rg,
					Subscription:  sub,
					Location:      str(srv.Location),
				}
				if p := srv.Properties; p != nil {
					// Treat only an explicit Enabled as public; a nil flag is not
					// flagged, avoiding a false positive when the API omits it.
					s.PublicNetworkAccess = p.PublicNetworkAccess != nil &&
						*p.PublicNetworkAccess == armsql.ServerNetworkAccessFlagEnabled
					s.MinTLSVersion = str(p.MinimalTLSVersion)
				}
				s.FirewallRules = collectSQLFirewallRules(sc, fwClient, rg, name)
				st.AddSQLServer(s)
			}
		}
	}
	return errors.Join(errs...)
}

// collectSQLFirewallRules lists one server's firewall rules. A read failure
// yields no rules (the firewall-allow-all check simply finds nothing) rather
// than dropping the server's other posture.
func collectSQLFirewallRules(sc *engine.ScanContext, client *armsql.FirewallRulesClient, rg, server string) []state.SQLFirewallRule {
	var rules []state.SQLFirewallRule
	pager := client.NewListByServerPager(rg, server, nil)
	for pager.More() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return rules
		}
		for _, r := range page.Value {
			if r == nil || r.Properties == nil {
				continue
			}
			rules = append(rules, state.SQLFirewallRule{
				Name:    str(r.Name),
				StartIP: str(r.Properties.StartIPAddress),
				EndIP:   str(r.Properties.EndIPAddress),
			})
		}
	}
	return rules
}
