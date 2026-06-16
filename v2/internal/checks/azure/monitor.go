package azure

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(monitorActivityAlertMissing{}) }

// cisAlertOperations are the sensitive control-plane operations CIS Azure 5.2
// requires an activity-log alert for.
var cisAlertOperations = []struct{ op, label string }{
	{"Microsoft.Authorization/policyAssignments/write", "create/update policy assignment"},
	{"Microsoft.Authorization/policyAssignments/delete", "delete policy assignment"},
	{"Microsoft.Network/networkSecurityGroups/write", "create/update NSG"},
	{"Microsoft.Network/networkSecurityGroups/delete", "delete NSG"},
	{"Microsoft.Sql/servers/firewallRules/write", "create/update SQL firewall rule"},
	{"Microsoft.Sql/servers/firewallRules/delete", "delete SQL firewall rule"},
	{"Microsoft.Security/securitySolutions/write", "create/update security solution"},
	{"Microsoft.Security/securitySolutions/delete", "delete security solution"},
	{"Microsoft.Network/publicIPAddresses/write", "create/update public IP"},
	{"Microsoft.Network/publicIPAddresses/delete", "delete public IP"},
}

type monitorActivityAlertMissing struct{}

func (monitorActivityAlertMissing) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_monitor_activity_alert_missing", Title: "No activity-log alert for a sensitive operation",
		Provider: "azure", Service: "monitor", Severity: findings.SeverityMedium,
		Rationale:   "CIS requires an activity-log alert for sensitive control-plane operations (policy, NSG, SQL firewall, security solution, public IP changes) so they raise a real-time alert. Without it, those changes occur unnoticed.",
		Impact:      "Risky configuration changes are not alerted, delaying detection and response.",
		Remediation: "Create an activity-log alert for the operation: az monitor activity-log alert create --name <name> --condition category=Administrative and operationName=<op>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "5.2.x"}},
	}
}

func (c monitorActivityAlertMissing) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, m := range st.Azure.Monitors {
		if !m.AlertsReadOK {
			continue // alerts not collected — do not fabricate "all missing"
		}
		covered := make(map[string]bool, len(m.AlertedOperations))
		for _, op := range m.AlertedOperations {
			covered[strings.ToLower(op)] = true
		}
		for _, req := range cisAlertOperations {
			if covered[strings.ToLower(req.op)] {
				continue
			}
			res := findings.Resource{
				ID: m.Subscription + ":" + req.op, Name: req.label, Type: "azure_subscription", Provider: "azure", Account: m.Subscription,
			}
			desc := fmt.Sprintf("Subscription %s has no activity-log alert for %s (%s).", m.Subscription, req.label, req.op)
			poc := fmt.Sprintf("az monitor activity-log alert list --subscription %s", m.Subscription)
			out = append(out, findings.New(c.Spec(), res, desc, poc, now))
		}
	}
	return out, nil
}
