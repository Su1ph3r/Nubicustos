package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(ecrPublicPolicy{})
	engine.RegisterCheck(ecrScanOnPushDisabled{})
}

func ecrResource(r state.ECRRepository) findings.Resource {
	return findings.Resource{
		ID: r.Name, Name: r.Name, Type: "aws_ecr_repository", Provider: "aws", Region: r.Region,
	}
}

type ecrPublicPolicy struct{}

func (ecrPublicPolicy) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ecr_repository_public_policy", Title: "ECR repository policy grants public access",
		Provider: "aws", Service: "ecr", Severity: findings.SeverityHigh,
		Rationale:   "A repository policy allowing Principal \"*\" with no condition lets any AWS account (or anonymous caller, per action) pull — or potentially push — images, exposing or tampering with the supply chain.",
		Impact:      "External parties can pull private images (IP/secret disclosure) or push tampered images consumed by workloads.",
		Remediation: "Scope the policy to specific principals: aws ecr set-repository-policy --repository-name <name> --policy-text <scoped>",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c ecrPublicPolicy) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, r := range st.AWS.ECRRepos {
		if !r.PublicPolicy {
			continue
		}
		desc := fmt.Sprintf("ECR repository %q (%s) has a policy granting a wildcard principal with no condition.", r.Name, r.Region)
		poc := fmt.Sprintf("aws ecr get-repository-policy --repository-name %s --region %s", r.Name, r.Region)
		out = append(out, findings.New(c.Spec(), ecrResource(r), desc, poc, now))
	}
	return out, nil
}

type ecrScanOnPushDisabled struct{}

func (ecrScanOnPushDisabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ecr_scan_on_push_disabled", Title: "ECR repository does not scan images on push",
		Provider: "aws", Service: "ecr", Severity: findings.SeverityLow,
		Rationale:   "Without scan-on-push, image vulnerabilities are not detected as images enter the registry, so known-vulnerable images can be deployed unnoticed.",
		Impact:      "Vulnerable images reach workloads without a vulnerability gate at push time.",
		Remediation: "Enable scan-on-push: aws ecr put-image-scanning-configuration --repository-name <name> --image-scanning-configuration scanOnPush=true",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-AppSec"}},
	}
}

func (c ecrScanOnPushDisabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, r := range st.AWS.ECRRepos {
		if r.ScanOnPush {
			continue
		}
		desc := fmt.Sprintf("ECR repository %q (%s) does not scan images on push.", r.Name, r.Region)
		poc := fmt.Sprintf("aws ecr describe-repositories --repository-names %s --region %s --query 'repositories[].imageScanningConfiguration'", r.Name, r.Region)
		out = append(out, findings.New(c.Spec(), ecrResource(r), desc, poc, now))
	}
	return out, nil
}
