package gcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(monitoringAlertMissing{}) }

// gcpMonitoringControl is a CIS GCP section-2 monitoring requirement: the change
// it covers and the signature tokens identifying a log-based metric for it.
type gcpMonitoringControl struct {
	cis   string
	label string
	all   []string
	any   []string
}

var cisGCPMonitoringControls = []gcpMonitoringControl{
	{"2.4", "project ownership changes", nil, []string{"ProjectOwnership", "projectOwnerInvitee"}},
	{"2.5", "audit configuration changes", nil, []string{"auditConfigDeltas"}},
	{"2.6", "custom role changes", nil, []string{"iam_role"}},
	{"2.7", "VPC firewall rule changes", nil, []string{"gce_firewall_rule"}},
	{"2.8", "VPC network route changes", nil, []string{"gce_route"}},
	{"2.9", "VPC network changes", nil, []string{"gce_network"}},
	{"2.10", "Cloud Storage IAM permission changes", []string{"gcs_bucket", "SetIamPolicy"}, nil},
	{"2.11", "SQL instance configuration changes", nil, []string{"cloudsql_database"}},
}

type monitoringAlertMissing struct{}

func (monitoringAlertMissing) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_monitoring_alert_missing", Title: "No log metric + alert for a sensitive change",
		Provider: "gcp", Service: "monitoring", Severity: findings.SeverityMedium,
		Rationale:   "CIS requires a log-based metric and an alert policy for sensitive changes (project ownership, audit config, custom roles, firewall/route/network, storage IAM, SQL config) so they raise a real-time alert. Without it, those changes occur unnoticed.",
		Impact:      "Risky control-plane changes are not alerted, delaying detection and response.",
		Remediation: "Create a log-based metric matching the event and an alert policy on it: gcloud logging metrics create <name> --log-filter='<filter>' && gcloud alpha monitoring policies create ...",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "2.x"}},
	}
}

func (c monitoringAlertMissing) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, m := range st.GCP.Monitoring {
		if !m.ReadOK {
			continue // not collected — do not fabricate "all missing"
		}
		alerted := make(map[string]bool, len(m.AlertedMetricNames))
		for _, n := range m.AlertedMetricNames {
			alerted[n] = true
		}
		for _, ctrl := range cisGCPMonitoringControls {
			if gcpMonitoredAndAlerted(m.Metrics, alerted, ctrl) {
				continue
			}
			res := findings.Resource{
				ID: m.Project + ":cis-" + ctrl.cis, Name: "CIS " + ctrl.cis, Type: "gcp_project", Provider: "gcp", Account: m.Project,
			}
			desc := fmt.Sprintf("Project %s has no log metric with an alert for %s (CIS %s).", m.Project, ctrl.label, ctrl.cis)
			poc := fmt.Sprintf("gcloud logging metrics list --project %s && gcloud alpha monitoring policies list --project %s", m.Project, m.Project)
			out = append(out, findings.New(c.Spec(), res, desc, poc, now))
		}
	}
	return out, nil
}

func gcpMonitoredAndAlerted(metrics []state.GCPLogMetric, alerted map[string]bool, ctrl gcpMonitoringControl) bool {
	for _, m := range metrics {
		if !gcpFilterMatches(m.Filter, ctrl) {
			continue
		}
		// The metric name reaches the alert filter as logging.googleapis.com/user/<short>,
		// where <short> is the metric's short name (the last path segment).
		if alerted[shortMetricName(m.Name)] || alerted[m.Name] {
			return true
		}
	}
	return false
}

func gcpFilterMatches(filter string, ctrl gcpMonitoringControl) bool {
	if len(ctrl.all) > 0 {
		for _, tok := range ctrl.all {
			if !strings.Contains(filter, tok) {
				return false
			}
		}
		return true
	}
	for _, tok := range ctrl.any {
		if strings.Contains(filter, tok) {
			return true
		}
	}
	return false
}

// shortMetricName returns a log metric's short name (the segment after the final
// "/" in projects/<p>/metrics/<short>, or the value itself if already short).
func shortMetricName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}
