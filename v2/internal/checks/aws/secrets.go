package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(secretsRotation{}) }

// secretsRotation flags Secrets Manager secrets without automatic rotation,
// aggregated into a single finding listing every affected secret.
type secretsRotation struct{}

func (secretsRotation) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_secretsmanager_rotation_disabled", Title: "Secrets Manager secret does not have rotation enabled",
		Provider: "aws", Service: "secretsmanager", Severity: findings.SeverityMedium,
		Rationale:   "Automatic rotation limits the window a leaked secret remains valid; static secrets persist indefinitely.",
		Impact:      "A leaked static secret remains usable until manually changed, extending the compromise window.",
		Remediation: "Configure rotation: aws secretsmanager rotate-secret --secret-id <arn> --rotation-lambda-arn <arn> --rotation-rules AutomaticallyAfterDays=30",
		PoC:         "aws secretsmanager list-secrets --query 'SecretList[?RotationEnabled==`false`].ARN'",
	}
}

func (c secretsRotation) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for _, s := range st.AWS.Secrets {
		if s.RotationEnabled {
			continue
		}
		items = append(items, findings.Affected{Type: "secret", ID: s.Name, Region: s.Region, ARN: s.ARN})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d Secrets Manager secret(s) do not have automatic rotation enabled.", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}
