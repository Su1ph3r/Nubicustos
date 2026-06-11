// Package gcp contains native GCP posture checks. Checks read collected state
// and emit findings; they never call cloud APIs. Each check pairs a CheckSpec
// with per-resource finding generation, mirroring the AWS/Azure checks.
package gcp

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(bucketPublic{})
	engine.RegisterCheck(bucketUniformAccess{})
	engine.RegisterCheck(bucketPublicAccessPrevention{})
}

func bucketResource(b state.GCSBucket) findings.Resource {
	return findings.Resource{
		ID: b.Name, Name: b.Name, Type: "gcp_storage_bucket", Provider: "gcp",
		Account: b.Project, Region: b.Location,
	}
}

type bucketPublic struct{}

func (bucketPublic) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_gcs_bucket_public", Title: "Cloud Storage bucket is publicly accessible",
		Provider: "gcp", Service: "storage", Severity: findings.SeverityHigh,
		Rationale:   "An IAM binding to allUsers or allAuthenticatedUsers lets anyone on the internet read the bucket.",
		Impact:      "Unauthenticated callers can list and read the bucket's objects.",
		Remediation: "Remove the public member: gsutil iam ch -d allUsers gs://<bucket> (and allAuthenticatedUsers)",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "5.1"}},
	}
}

func (c bucketPublic) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, b := range st.GCP.Buckets {
		if !b.PublicIAM {
			continue
		}
		desc := fmt.Sprintf("Bucket %q (project %s) grants public access via its IAM policy.", b.Name, b.Project)
		poc := fmt.Sprintf("gsutil iam get gs://%s", b.Name)
		out = append(out, findings.New(c.Spec(), bucketResource(b), desc, poc, now))
	}
	return out, nil
}

type bucketUniformAccess struct{}

func (bucketUniformAccess) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_gcs_uniform_access_disabled", Title: "Cloud Storage bucket does not enforce uniform bucket-level access",
		Provider: "gcp", Service: "storage", Severity: findings.SeverityLow,
		Rationale:   "With legacy ACLs enabled, per-object ACLs can grant access that bypasses IAM, making exposure hard to reason about.",
		Impact:      "Object-level ACLs can expose data even when bucket IAM looks restrictive.",
		Remediation: "gsutil uniformbucketlevelaccess set on gs://<bucket>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "5.2"}},
	}
}

func (c bucketUniformAccess) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, b := range st.GCP.Buckets {
		if b.UniformBucketLevelAccess {
			continue
		}
		desc := fmt.Sprintf("Bucket %q does not enforce uniform bucket-level access (legacy ACLs are active).", b.Name)
		poc := fmt.Sprintf("gsutil uniformbucketlevelaccess get gs://%s", b.Name)
		out = append(out, findings.New(c.Spec(), bucketResource(b), desc, poc, now))
	}
	return out, nil
}

type bucketPublicAccessPrevention struct{}

func (bucketPublicAccessPrevention) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_gcs_public_access_prevention_disabled", Title: "Cloud Storage bucket does not enforce public access prevention",
		Provider: "gcp", Service: "storage", Severity: findings.SeverityMedium,
		Rationale:   "Public access prevention blocks any IAM/ACL grant that would make the bucket public; when not enforced, a future misconfiguration can expose it.",
		Impact:      "The bucket can be made public by a single accidental or malicious grant.",
		Remediation: "gsutil pap set enforced gs://<bucket>",
	}
}

func (c bucketPublicAccessPrevention) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, b := range st.GCP.Buckets {
		if b.PublicAccessPrevention == "enforced" {
			continue
		}
		desc := fmt.Sprintf("Bucket %q does not enforce public access prevention (%q).", b.Name, b.PublicAccessPrevention)
		poc := fmt.Sprintf("gsutil pap get gs://%s", b.Name)
		out = append(out, findings.New(c.Spec(), bucketResource(b), desc, poc, now))
	}
	return out, nil
}
