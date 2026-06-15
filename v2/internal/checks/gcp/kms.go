package gcp

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(kmsRotationDisabled{})
	engine.RegisterCheck(kmsPublicIAM{})
}

func kmsResource(k state.KMSCryptoKey) findings.Resource {
	return findings.Resource{
		ID: k.KeyRing + "/" + k.Name, Name: k.Name, Type: "gcp_kms_crypto_key", Provider: "gcp",
		Account: k.Project, Region: k.Location,
	}
}

type kmsRotationDisabled struct{}

func (kmsRotationDisabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_kms_key_rotation_disabled", Title: "KMS encryption key has no rotation configured",
		Provider: "gcp", Service: "kms", Severity: findings.SeverityMedium,
		Rationale:   "An ENCRYPT_DECRYPT key with no rotation period never rotates, so a single key compromise exposes all data ever encrypted with it and there is no key-version boundary to limit blast radius.",
		Impact:      "A leaked key version decrypts the full history of data protected by the key.",
		Remediation: "Set a rotation period (CIS recommends <= 90 days): gcloud kms keys update <key> --keyring <ring> --location <loc> --rotation-period=90d --next-rotation-time=<ts>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "1.10"}},
	}
}

func (c kmsRotationDisabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, k := range st.GCP.KMSKeys {
		// Only symmetric ENCRYPT_DECRYPT keys support automatic rotation; asymmetric
		// signing/verification keys do not, so they are not flagged.
		if k.Purpose != "ENCRYPT_DECRYPT" || k.RotationEnabled {
			continue
		}
		desc := fmt.Sprintf("KMS key %q (ring %s, project %s) has no rotation period configured.", k.Name, k.KeyRing, k.Project)
		poc := fmt.Sprintf("gcloud kms keys describe %s --keyring %s --location %s --project %s --format='value(rotationPeriod)'", k.Name, k.KeyRing, k.Location, k.Project)
		out = append(out, findings.New(c.Spec(), kmsResource(k), desc, poc, now))
	}
	return out, nil
}

type kmsPublicIAM struct{}

func (kmsPublicIAM) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_kms_key_public_iam", Title: "KMS key IAM policy grants public access",
		Provider: "gcp", Service: "kms", Severity: findings.SeverityHigh,
		Rationale:   "A KMS key whose IAM policy includes allUsers or allAuthenticatedUsers lets anyone (or any Google account) use the key to encrypt/decrypt, defeating its purpose as an access boundary.",
		Impact:      "An external party can decrypt data protected by the key or encrypt malicious data under a trusted key.",
		Remediation: "Remove the public principal: gcloud kms keys remove-iam-policy-binding <key> --keyring <ring> --location <loc> --member=allUsers --role=<role>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "1.9"}},
	}
}

func (c kmsPublicIAM) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, k := range st.GCP.KMSKeys {
		if !k.PublicIAM {
			continue
		}
		desc := fmt.Sprintf("KMS key %q (ring %s) grants public access in its IAM policy.", k.Name, k.KeyRing)
		poc := fmt.Sprintf("gcloud kms keys get-iam-policy %s --keyring %s --location %s --project %s", k.Name, k.KeyRing, k.Location, k.Project)
		out = append(out, findings.New(c.Spec(), kmsResource(k), desc, poc, now))
	}
	return out, nil
}
