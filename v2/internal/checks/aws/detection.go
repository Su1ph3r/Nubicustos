package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(kmsRotation{})
	engine.RegisterCheck(configRecording{})
	engine.RegisterCheck(guarddutyEnabled{})
}

// --- KMS key rotation -------------------------------------------------------

type kmsRotation struct{}

func (kmsRotation) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_kms_cmk_rotation_disabled", Title: "Customer-managed KMS key does not have rotation enabled",
		Provider: "aws", Service: "kms", Severity: findings.SeverityMedium,
		Rationale:   "Annual key rotation limits the amount of data encrypted under any single key version, reducing blast radius if a key is compromised.",
		Impact:      "A long-lived static key encrypts more data over time; a compromise exposes a larger dataset.",
		Remediation: "Enable rotation: aws kms enable-key-rotation --key-id <id>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "3.6"}},
	}
}

func (c kmsRotation) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, k := range st.AWS.KMSKeys {
		if !k.CustomerManaged || !k.Enabled || k.RotationEnabled {
			continue
		}
		res := regionalResource(st.AWS.Account, k.Region, k.ID, "aws_kms_key",
			fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", k.Region, st.AWS.Account, k.ID))
		desc := fmt.Sprintf("Customer-managed KMS key %s in %s does not have automatic rotation enabled.", k.ID, k.Region)
		poc := fmt.Sprintf("aws kms get-key-rotation-status --key-id %s --region %s", k.ID, k.Region)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// --- AWS Config recording ---------------------------------------------------

type configRecording struct{}

func (configRecording) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_config_not_recording", Title: "AWS Config is not recording in a region",
		Provider: "aws", Service: "config", Severity: findings.SeverityMedium,
		Rationale:   "AWS Config provides the configuration history and change tracking that posture monitoring and incident response depend on.",
		Impact:      "Configuration changes in the region are not recorded, so drift and tampering cannot be reconstructed.",
		Remediation: "Enable a recorder for all supported resources and start it: aws configservice put-configuration-recorder ... && aws configservice start-configuration-recorder --configuration-recorder-name default",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "3.3"}},
	}
}

func (c configRecording) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for region, status := range st.AWS.ConfigByRegion {
		if status.Recording && status.AllSupported {
			continue
		}
		items = append(items, findings.Affected{Type: "region", Region: region})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("AWS Config is not recording all supported resources in %d of %d scanned region(s).",
		len(items), len(st.AWS.ConfigByRegion))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}

// --- GuardDuty enabled ------------------------------------------------------

type guarddutyEnabled struct{}

func (guarddutyEnabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_guardduty_not_enabled", Title: "GuardDuty is not enabled in a region",
		Provider: "aws", Service: "guardduty", Severity: findings.SeverityMedium,
		Rationale:   "GuardDuty is the managed threat-detection service; without it, malicious activity in the region goes undetected.",
		Impact:      "Reconnaissance, credential abuse, and other threats in the region are not detected or alerted on.",
		Remediation: "Enable it: aws guardduty create-detector --enable --region <region>",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC04-BP01"}},
	}
}

func (c guarddutyEnabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for region, enabled := range st.AWS.GuardDutyEnabledByRegion {
		if enabled {
			continue
		}
		items = append(items, findings.Affected{Type: "region", Region: region})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("GuardDuty has no enabled detector in %d of %d scanned region(s).",
		len(items), len(st.AWS.GuardDutyEnabledByRegion))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}
