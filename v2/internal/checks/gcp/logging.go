package gcp

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(auditLoggingNotConfigured{}) }

type auditLoggingNotConfigured struct{}

func (auditLoggingNotConfigured) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_audit_logging_not_configured", Title: "Project does not log data-access audit events for all services",
		Provider: "gcp", Service: "logging", Severity: findings.SeverityMedium,
		Rationale:   "Without an allServices audit config capturing DATA_READ and DATA_WRITE, data-access activity goes unrecorded, so unauthorized reads/writes leave no audit trail for detection or forensics.",
		Impact:      "Data exfiltration and tampering cannot be detected or investigated after the fact.",
		Remediation: "Enable data-access audit logging for all services in the project IAM policy (auditConfigs: allServices with DATA_READ and DATA_WRITE log types).",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "2.1"}},
	}
}

func (c auditLoggingNotConfigured) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.GCP.AuditConfig {
		// Only judge projects whose policy was actually read; a denied project must
		// not be reported as "not logging".
		if !a.Collected || (a.DataReadAll && a.DataWriteAll) {
			continue
		}
		res := findings.Resource{
			ID: a.Project, Name: a.Project, Type: "gcp_project", Provider: "gcp", Account: a.Project,
		}
		desc := fmt.Sprintf("Project %s does not log data-access audit events for all services (DATA_READ=%t, DATA_WRITE=%t).", a.Project, a.DataReadAll, a.DataWriteAll)
		poc := fmt.Sprintf("gcloud projects get-iam-policy %s --format='value(auditConfigs)'", a.Project)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
