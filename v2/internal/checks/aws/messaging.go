package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(snsPublicPolicy{})
	engine.RegisterCheck(sqsPublicPolicy{})
}

type snsPublicPolicy struct{}

func (snsPublicPolicy) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_sns_topic_public_policy", Title: "SNS topic policy grants public access",
		Provider: "aws", Service: "sns", Severity: findings.SeverityHigh,
		Rationale:   "An SNS topic policy allowing Principal \"*\" with no restricting condition lets any AWS account (or anonymous caller, per action) subscribe to or publish to the topic.",
		Impact:      "External parties can read messages by subscribing, or inject messages by publishing, crossing the account boundary.",
		Remediation: "Scope the statement to specific principals or add a SourceArn/SourceAccount condition: aws sns set-topic-attributes --topic-arn <arn> --attribute-name Policy --attribute-value <scoped>",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c snsPublicPolicy) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return messagingFindings(st, "sns", c.Spec(), "SNS topic", "aws sns get-topic-attributes --topic-arn %s")
}

type sqsPublicPolicy struct{}

func (sqsPublicPolicy) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_sqs_queue_public_policy", Title: "SQS queue policy grants public access",
		Provider: "aws", Service: "sqs", Severity: findings.SeverityHigh,
		Rationale:   "An SQS queue policy allowing Principal \"*\" with no restricting condition lets any AWS account send to or receive from the queue.",
		Impact:      "External parties can drain messages (data disclosure) or inject messages (integrity/abuse), crossing the account boundary.",
		Remediation: "Scope the statement to specific principals or add a SourceArn/SourceAccount condition: aws sqs set-queue-attributes --queue-url <url> --attributes Policy=<scoped>",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c sqsPublicPolicy) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return messagingFindings(st, "sqs", c.Spec(), "SQS queue", "aws sqs get-queue-attributes --queue-url %s --attribute-names Policy")
}

// messagingFindings emits a finding per public-policy resource of the given
// service, shared by the SNS and SQS checks.
func messagingFindings(st *state.State, service string, spec findings.CheckSpec, label, pocFmt string) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, m := range st.AWS.Messaging {
		if m.Service != service || !m.PublicPolicy {
			continue
		}
		res := findings.Resource{
			ID: m.ID, Name: m.Name, Type: "aws_" + service, Provider: "aws", Region: m.Region,
		}
		desc := fmt.Sprintf("%s %q (%s) has a resource policy granting a wildcard principal with no condition.", label, m.Name, m.Region)
		out = append(out, findings.New(spec, res, desc, fmt.Sprintf(pocFmt, m.ID), now))
	}
	return out, nil
}
