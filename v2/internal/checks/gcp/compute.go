package gcp

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(computeDefaultSAFullAPI{})
	engine.RegisterCheck(computeShieldedDisabled{})
	engine.RegisterCheck(computeSerialPort{})
}

func computeResource(i state.ComputeInstance) findings.Resource {
	return findings.Resource{
		ID: i.Name, Name: i.Name, Type: "gcp_compute_instance", Provider: "gcp",
		Account: i.Project, Region: i.Zone,
	}
}

type computeDefaultSAFullAPI struct{}

func (computeDefaultSAFullAPI) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_compute_default_sa_full_api", Title: "VM uses the default service account with full API access",
		Provider: "gcp", Service: "compute", Severity: findings.SeverityHigh,
		Rationale:   "A VM running as the default Compute Engine service account with the cloud-platform scope can call almost any GCP API as that highly-privileged identity. Anyone who compromises the VM inherits that access.",
		Impact:      "Code execution on the VM (e.g. via an app vulnerability) escalates to broad project-wide API access through the instance's token endpoint.",
		Remediation: "Use a dedicated least-privilege service account and scoped access: gcloud compute instances set-service-account <name> --service-account=<sa> --scopes=<minimal>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "4.1"}},
	}
}

func (c computeDefaultSAFullAPI) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.ComputeVMs {
		if !i.DefaultSAFullAPI {
			continue
		}
		desc := fmt.Sprintf("VM %q (project %s) runs as the default Compute service account with full (cloud-platform) API access.", i.Name, i.Project)
		poc := fmt.Sprintf("gcloud compute instances describe %s --zone %s --project %s --format='value(serviceAccounts)'", i.Name, i.Zone, i.Project)
		out = append(out, findings.New(c.Spec(), computeResource(i), desc, poc, now))
	}
	return out, nil
}

type computeShieldedDisabled struct{}

func (computeShieldedDisabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_compute_shielded_vm_disabled", Title: "VM does not have Shielded VM fully enabled",
		Provider: "gcp", Service: "compute", Severity: findings.SeverityLow,
		Rationale:   "Shielded VM (secure boot + vTPM + integrity monitoring) protects against boot- and kernel-level rootkits and verifies instance integrity. With any component off, those protections are incomplete.",
		Impact:      "A compromised boot chain or kernel rootkit can persist undetected on the instance.",
		Remediation: "Enable all three: gcloud compute instances update <name> --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "4.8"}},
	}
}

func (c computeShieldedDisabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.ComputeVMs {
		if i.ShieldedVM {
			continue
		}
		desc := fmt.Sprintf("VM %q does not have Shielded VM fully enabled (secure boot + vTPM + integrity monitoring).", i.Name)
		poc := fmt.Sprintf("gcloud compute instances describe %s --zone %s --project %s --format='value(shieldedInstanceConfig)'", i.Name, i.Zone, i.Project)
		out = append(out, findings.New(c.Spec(), computeResource(i), desc, poc, now))
	}
	return out, nil
}

type computeSerialPort struct{}

func (computeSerialPort) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_compute_serial_port_enabled", Title: "VM has the interactive serial console enabled",
		Provider: "gcp", Service: "compute", Severity: findings.SeverityMedium,
		Rationale:   "The interactive serial console is reachable without firewall or network controls; if SSH keys or passwords are exposed it offers an out-of-band entry path that bypasses VPC restrictions.",
		Impact:      "An attacker with credentials can reach the instance over the serial console even when network access is otherwise blocked.",
		Remediation: "Disable it: gcloud compute instances add-metadata <name> --metadata serial-port-enable=false",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "4.5"}},
	}
}

func (c computeSerialPort) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, i := range st.GCP.ComputeVMs {
		if !i.SerialPortEnabled {
			continue
		}
		desc := fmt.Sprintf("VM %q has the interactive serial console enabled.", i.Name)
		poc := fmt.Sprintf("gcloud compute instances describe %s --zone %s --project %s --format='value(metadata.items)'", i.Name, i.Zone, i.Project)
		out = append(out, findings.New(c.Spec(), computeResource(i), desc, poc, now))
	}
	return out, nil
}
