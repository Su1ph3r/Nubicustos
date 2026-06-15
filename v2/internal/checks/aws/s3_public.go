// Package aws contains native AWS posture checks. Checks read collected state
// and emit findings; they never call cloud APIs themselves. Each check pairs a
// CheckSpec (static metadata) with per-resource finding generation.
package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(s3PublicAccess{}) }

// s3PublicAccess flags buckets that are publicly accessible (via ACL or policy)
// and not fully protected by a Public Access Block.
type s3PublicAccess struct{}

func (s3PublicAccess) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:        "aws_s3_public_access",
		Title:     "S3 bucket is publicly accessible",
		Provider:  "aws",
		Service:   "s3",
		Severity:  findings.SeverityHigh,
		Rationale: "Buckets reachable by anonymous or any-AWS principals expose their objects to the internet, a frequent source of data leaks.",
		Impact:    "An unauthenticated attacker can list and read (and depending on grants, write) objects in the bucket.",
		Remediation: "Enable Block Public Access on the bucket and remove public ACL grants / policy statements:\n" +
			"aws s3api put-public-access-block --bucket <name> --public-access-block-configuration " +
			"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
		Compliance: []findings.ComplianceRef{
			{Framework: "CIS AWS 3.0", Control: "2.1.4"},
		},
		References: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
	}
}

func (c s3PublicAccess) Evaluate(sc *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()

	var out []findings.Finding
	for _, b := range st.AWS.S3Buckets {
		public := b.ACLPublic || b.PolicyPublic
		if !public || b.FullyBlocked() {
			continue
		}

		res := findings.Resource{
			ID:       b.Name,
			Name:     b.Name,
			Type:     "aws_s3_bucket",
			Provider: "aws",
			Account:  st.AWS.Account,
			Region:   b.Region,
			ARN:      fmt.Sprintf("arn:aws:s3:::%s", b.Name),
		}

		via := publicVia(b)
		desc := fmt.Sprintf("Bucket %q in %s is publicly accessible via %s and is not fully protected by Block Public Access.",
			b.Name, b.Region, via)

		// PoC: prove anonymous read without credentials (the §9.1 validator binding).
		poc := fmt.Sprintf("aws s3api list-objects-v2 --bucket %s --no-sign-request --max-items 5", b.Name)

		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// publicVia describes how the bucket is exposed, for the finding description.
func publicVia(b state.S3Bucket) string {
	switch {
	case b.ACLPublic && b.PolicyPublic:
		return "a public ACL grant and a public bucket policy"
	case b.ACLPublic:
		return "a public ACL grant"
	default:
		return "a public bucket policy"
	}
}
