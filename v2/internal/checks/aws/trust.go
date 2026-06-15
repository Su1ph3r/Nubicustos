package aws

import (
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
	"github.com/Su1ph3r/nubicustos/internal/trust"
)

func init() { engine.RegisterCheck(iamTrustAnalysis{}) }

// iamTrustAnalysis is an umbrella check that surfaces the IAM trust and
// privilege findings produced by the trust analyzer (external/wildcard/OIDC
// trust, admin-via-custom-policy, privilege escalation). The analyzer assigns
// each finding its own specific CheckID; this Spec is the catalog entry that
// registers the analysis pass.
type iamTrustAnalysis struct{}

func (iamTrustAnalysis) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:          "aws_iam_trust_analysis",
		Title:       "IAM trust and privilege analysis",
		Provider:    "aws",
		Service:     "iam",
		Severity:    findings.SeverityHigh,
		Rationale:   "Over-broad role trust and concentrated/escalatable permissions are where account-takeover paths begin.",
		Impact:      "An attacker who satisfies a loose trust policy or compromises an over-privileged principal can reach account-wide control.",
		Remediation: "Scope role trust policies to specific principals with conditions, and apply least privilege to permission policies.",
	}
}

func (iamTrustAnalysis) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	return trust.Analyze(st.AWS).Findings, nil
}
