package gcp

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(cloudSQLPublicIP{})
	engine.RegisterCheck(cloudSQLNoSSL{})
	engine.RegisterCheck(cloudSQLAuthorizedAll{})
	engine.RegisterCheck(cloudSQLNoBackup{})
}

func cloudSQLResource(i state.CloudSQLInstance) findings.Resource {
	return findings.Resource{
		ID: i.Name, Name: i.Name, Type: "gcp_cloudsql_instance", Provider: "gcp",
		Account: i.Project, Region: i.Region,
	}
}

type cloudSQLPublicIP struct{}

func (cloudSQLPublicIP) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_cloudsql_public_ip", Title: "Cloud SQL instance has a public IP",
		Provider: "gcp", Service: "cloudsql", Severity: findings.SeverityMedium,
		Rationale:   "A Cloud SQL instance with a public IPv4 address is reachable from outside the VPC, exposing the database endpoint to the internet (subject to authorized networks).",
		Impact:      "The database endpoint can be reached by external hosts, widening the attack surface for credential and injection attacks.",
		Remediation: "Use private IP and disable the public address: gcloud sql instances patch <name> --no-assign-ip",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "6.5"}},
	}
}

func (c cloudSQLPublicIP) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.CloudSQL {
		if !i.PublicIP {
			continue
		}
		desc := fmt.Sprintf("Cloud SQL instance %q (project %s) has a public IP.", i.Name, i.Project)
		poc := fmt.Sprintf("gcloud sql instances describe %s --project %s --format='value(settings.ipConfiguration.ipv4Enabled)'", i.Name, i.Project)
		out = append(out, findings.New(c.Spec(), cloudSQLResource(i), desc, poc, now))
	}
	return out, nil
}

type cloudSQLNoSSL struct{}

func (cloudSQLNoSSL) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_cloudsql_ssl_not_required", Title: "Cloud SQL instance does not require SSL/TLS",
		Provider: "gcp", Service: "cloudsql", Severity: findings.SeverityMedium,
		Rationale:   "Without enforced SSL/TLS, clients can connect over unencrypted channels, exposing credentials and query data in transit.",
		Impact:      "Database traffic can be intercepted or tampered with on the network path.",
		Remediation: "Require encrypted connections: gcloud sql instances patch <name> --ssl-mode=ENCRYPTED_ONLY",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "6.4"}},
	}
}

func (c cloudSQLNoSSL) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.CloudSQL {
		if i.RequireSSL {
			continue
		}
		desc := fmt.Sprintf("Cloud SQL instance %q does not require SSL/TLS for connections.", i.Name)
		poc := fmt.Sprintf("gcloud sql instances describe %s --project %s --format='value(settings.ipConfiguration.sslMode)'", i.Name, i.Project)
		out = append(out, findings.New(c.Spec(), cloudSQLResource(i), desc, poc, now))
	}
	return out, nil
}

type cloudSQLAuthorizedAll struct{}

func (cloudSQLAuthorizedAll) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_cloudsql_authorized_network_all", Title: "Cloud SQL authorized networks include the entire internet",
		Provider: "gcp", Service: "cloudsql", Severity: findings.SeverityHigh,
		Rationale:   "An authorized network of 0.0.0.0/0 permits connections from every host on the internet, defeating network-level isolation.",
		Impact:      "Any host online can attempt to authenticate to the database, enabling brute-force and direct exploitation.",
		Remediation: "Remove the 0.0.0.0/0 entry and scope to required addresses: gcloud sql instances patch <name> --authorized-networks=<cidr>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "6.5"}},
	}
}

func (c cloudSQLAuthorizedAll) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.CloudSQL {
		if !i.OpenToInternet() {
			continue
		}
		desc := fmt.Sprintf("Cloud SQL instance %q authorizes the entire internet (0.0.0.0/0).", i.Name)
		poc := fmt.Sprintf("gcloud sql instances describe %s --project %s --format='value(settings.ipConfiguration.authorizedNetworks)'", i.Name, i.Project)
		out = append(out, findings.New(c.Spec(), cloudSQLResource(i), desc, poc, now))
	}
	return out, nil
}

type cloudSQLNoBackup struct{}

func (cloudSQLNoBackup) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_cloudsql_backup_disabled", Title: "Cloud SQL instance has automated backups disabled",
		Provider: "gcp", Service: "cloudsql", Severity: findings.SeverityLow,
		Rationale:   "Without automated backups there is no point-in-time recovery, so data loss from corruption, deletion, or ransomware is unrecoverable.",
		Impact:      "An incident affecting the database cannot be recovered to a prior state.",
		Remediation: "Enable automated backups: gcloud sql instances patch <name> --backup-start-time=<HH:MM>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "6.7"}},
	}
}

func (c cloudSQLNoBackup) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.CloudSQL {
		if i.BackupEnabled {
			continue
		}
		desc := fmt.Sprintf("Cloud SQL instance %q has automated backups disabled.", i.Name)
		poc := fmt.Sprintf("gcloud sql instances describe %s --project %s --format='value(settings.backupConfiguration.enabled)'", i.Name, i.Project)
		out = append(out, findings.New(c.Spec(), cloudSQLResource(i), desc, poc, now))
	}
	return out, nil
}
