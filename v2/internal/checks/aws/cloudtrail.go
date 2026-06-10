package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(cloudtrailEnabled{})
	engine.RegisterCheck(cloudtrailLogValidation{})
	engine.RegisterCheck(cloudtrailEncryption{})
}

func trailResource(account, region, name, arn string) findings.Resource {
	return findings.Resource{
		ID: arn, Name: name, Type: "aws_cloudtrail", Provider: "aws",
		Account: account, Region: region, ARN: arn,
	}
}

// --- account has a logging multi-region trail -------------------------------

type cloudtrailEnabled struct{}

func (cloudtrailEnabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_cloudtrail_no_logging_trail", Title: "No multi-region CloudTrail trail is logging",
		Provider: "aws", Service: "cloudtrail", Severity: findings.SeverityHigh,
		Rationale:   "Without an active multi-region trail, API activity is not recorded, blinding incident response and detection.",
		Impact:      "Attacker actions across the account go unrecorded; there is no audit trail to investigate or detect abuse.",
		Remediation: "Create a multi-region trail and start logging: aws cloudtrail create-trail --name org-trail --is-multi-region-trail --s3-bucket-name <bucket> && aws cloudtrail start-logging --name org-trail",
		PoC:         "aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`]'",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "3.1"}},
	}
}

func (c cloudtrailEnabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	for _, t := range st.AWS.Trails {
		if t.MultiRegion && t.IsLogging {
			return nil, nil // account is covered
		}
	}
	res := accountResource(st.AWS.Account)
	desc := "The account has no multi-region CloudTrail trail that is actively logging."
	return []findings.Finding{findings.New(c.Spec(), res, desc, c.Spec().PoC, time.Now().UTC())}, nil
}

// --- per-trail log-file validation ------------------------------------------

type cloudtrailLogValidation struct{}

func (cloudtrailLogValidation) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_cloudtrail_log_validation_disabled", Title: "CloudTrail log file validation is disabled",
		Provider: "aws", Service: "cloudtrail", Severity: findings.SeverityMedium,
		Rationale:   "Log file validation produces a digest that detects tampering or deletion of trail logs.",
		Impact:      "An attacker could alter or delete log files without detection, destroying audit integrity.",
		Remediation: "Enable validation: aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "3.2"}},
	}
}

func (c cloudtrailLogValidation) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, t := range st.AWS.Trails {
		if t.LogValidation {
			continue
		}
		res := trailResource(st.AWS.Account, t.HomeRegion, t.Name, t.ARN)
		desc := fmt.Sprintf("CloudTrail trail %q does not have log file validation enabled.", t.Name)
		poc := fmt.Sprintf("aws cloudtrail get-trail --name %s --query 'Trail.LogFileValidationEnabled'", t.Name)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// --- per-trail KMS encryption -----------------------------------------------

type cloudtrailEncryption struct{}

func (cloudtrailEncryption) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_cloudtrail_not_encrypted", Title: "CloudTrail logs are not encrypted with KMS",
		Provider: "aws", Service: "cloudtrail", Severity: findings.SeverityLow,
		Rationale:   "SSE-KMS encryption adds an access-control barrier on the log data beyond bucket permissions.",
		Impact:      "Trail logs rely solely on bucket controls; KMS would add defense in depth on sensitive audit data.",
		Remediation: "Set a KMS key: aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "3.5"}},
	}
}

func (c cloudtrailEncryption) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, t := range st.AWS.Trails {
		if t.KMSEncrypted {
			continue
		}
		res := trailResource(st.AWS.Account, t.HomeRegion, t.Name, t.ARN)
		desc := fmt.Sprintf("CloudTrail trail %q is not encrypted with a KMS key.", t.Name)
		poc := fmt.Sprintf("aws cloudtrail get-trail --name %s --query 'Trail.KmsKeyId'", t.Name)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}
