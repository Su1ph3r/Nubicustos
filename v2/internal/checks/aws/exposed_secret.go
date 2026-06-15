package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(exposedSecret{}) }

// exposedSecret reports credential material the secrets collector (§9.2) found
// embedded in the AWS control plane: Lambda env vars, EC2 userdata, SSM
// parameters. Anyone with read access to that configuration — a far broader set
// than the secret's intended consumers — can read these, so an exposed
// credential is a real disclosure regardless of whether it is still live.
//
// Every hit is aggregated into one finding whose Affected list enumerates each
// detection, carrying only the masked rendering (last four characters). Liveness
// is not asserted here; the opt-in active-validation pass (§9.1) is where a found
// credential is confirmed live/expired against its provider.
type exposedSecret struct{}

func (exposedSecret) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:        "aws_exposed_secret",
		Title:     "Secret material embedded in the cloud control plane",
		Provider:  "aws",
		Service:   "secrets",
		Severity:  findings.SeverityHigh,
		Rationale: "Credentials placed in Lambda env vars, EC2 userdata, or plaintext SSM parameters are readable by every principal with configuration-read access — a much wider audience than the secret's intended consumers — and are routinely harvested after an initial foothold.",
		Impact:    "An attacker reading the control plane lifts the credential and uses it directly (lateral movement, data access, privilege escalation), often without touching the resource it protects.",
		Remediation: "Move the value into Secrets Manager or an SSM SecureString and reference it at runtime; rotate the exposed credential, since it must be treated as compromised:\n" +
			"aws secretsmanager create-secret --name <name> --secret-string <value>  # then reference, and rotate the leaked one",
		PoC: "aws lambda get-function-configuration --function-name <fn> --query 'Environment.Variables'  # or ec2 describe-instance-attribute --attribute userData / ssm get-parameter",
		References: []string{
			"https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-securestring.html",
		},
	}
}

func (c exposedSecret) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for _, h := range st.AWS.SecretHits {
		items = append(items, findings.Affected{
			Type:   "secret",
			ID:     h.Resource,
			Region: h.Region,
			Detail: fmt.Sprintf("%s (%s) in %s %s [%s] at %q",
				h.Kind, h.Detector, surfaceLabel(h.Surface), h.Resource, h.Masked, h.Locator),
		})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d secret(s) are embedded in the AWS control plane (Lambda env / EC2 userdata / SSM parameters). Values are shown masked; rotate each, as exposure means compromise.", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}

// surfaceLabel renders a state surface id for the finding detail.
func surfaceLabel(surface string) string {
	switch surface {
	case "lambda_env":
		return "Lambda env var"
	case "ec2_userdata":
		return "EC2 userdata"
	case "ssm_parameter":
		return "SSM parameter"
	default:
		return surface
	}
}
