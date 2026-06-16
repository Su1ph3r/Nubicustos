package aws

import (
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(cloudWatchMonitoring{}) }

// monitoringControl is one CIS "log metric filter + alarm" requirement: the
// event it covers and the signature tokens that identify a metric filter for it.
// A control is satisfied when some metric filter's pattern contains ALL of its
// "all" tokens (or ANY of its "any" tokens) AND that filter's metric has an alarm.
type monitoringControl struct {
	cis   string // CIS AWS 3.0 control number
	label string
	all   []string // every token must appear in the filter pattern
	any   []string // at least one token must appear (used when all is empty)
}

// cisMonitoringControls is the CIS AWS section-4 monitoring set (the log-metric-
// filter + alarm controls). Tokens match the CloudTrail event signatures the CIS
// reference filter patterns key on, tolerant of pattern-formatting variation.
var cisMonitoringControls = []monitoringControl{
	{"4.1", "unauthorized API calls", nil, []string{"UnauthorizedOperation", "AccessDenied"}},
	{"4.2", "console sign-in without MFA", []string{"ConsoleLogin", "MFAUsed"}, nil},
	{"4.3", "root account usage", []string{"userIdentity.type", "Root"}, nil},
	{"4.4", "IAM policy changes", nil, []string{"DeleteUserPolicy", "PutUserPolicy", "DeleteRolePolicy", "PutRolePolicy", "AttachRolePolicy", "AttachUserPolicy", "CreatePolicyVersion", "DeleteGroupPolicy", "PutGroupPolicy"}},
	{"4.5", "CloudTrail configuration changes", nil, []string{"CreateTrail", "UpdateTrail", "DeleteTrail", "StopLogging", "StartLogging"}},
	{"4.6", "console authentication failures", []string{"ConsoleLogin", "Failed authentication"}, nil},
	{"4.7", "CMK disable or scheduled deletion", nil, []string{"DisableKey", "ScheduleKeyDeletion"}},
	{"4.8", "S3 bucket policy changes", nil, []string{"PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy", "PutBucketCors", "DeleteBucketCors"}},
	{"4.9", "AWS Config configuration changes", nil, []string{"PutConfigurationRecorder", "StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel"}},
	{"4.10", "security group changes", nil, []string{"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"}},
	{"4.11", "network ACL changes", nil, []string{"CreateNetworkAcl", "DeleteNetworkAcl", "ReplaceNetworkAclEntry", "CreateNetworkAclEntry", "DeleteNetworkAclEntry"}},
	{"4.12", "network gateway changes", nil, []string{"CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"}},
	{"4.13", "route table changes", nil, []string{"CreateRoute", "CreateRouteTable", "ReplaceRoute", "DeleteRoute", "DeleteRouteTable"}},
	{"4.14", "VPC changes", nil, []string{"CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "CreateVpcPeering", "DeleteVpcPeering"}},
	{"4.15", "organization changes", nil, []string{"organizations.amazonaws.com", "AcceptHandshake", "AttachPolicy", "CreateAccount", "RemoveAccountFromOrganization"}},
}

type cloudWatchMonitoring struct{}

func (cloudWatchMonitoring) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_monitoring_alarm_missing", Title: "CloudWatch log metric filter + alarm missing for a sensitive event",
		Provider: "aws", Service: "cloudwatch", Severity: findings.SeverityMedium,
		Rationale:   "CIS requires a CloudWatch Logs metric filter and an alarm for sensitive CloudTrail events (root usage, unauthorized calls, IAM/SG/NACL/route/VPC changes, etc.) so unauthorized or risky activity raises a real-time alert. Without it, those events occur silently.",
		Impact:      "Sensitive control-plane changes and suspicious activity go undetected and unalerted, slowing or preventing incident response.",
		Remediation: "Create a metric filter on the CloudTrail log group matching the event pattern and attach an alarm with an SNS action: aws logs put-metric-filter ... && aws cloudwatch put-metric-alarm ...",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "4.x"}},
	}
}

func (c cloudWatchMonitoring) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	// Without any log/alarm data collected, we cannot judge coverage — emitting a
	// finding per control would be a confident-but-unfounded fail. Skip cleanly.
	if len(st.AWS.LogMetricFilters) == 0 && len(st.AWS.AlarmedMetrics) == 0 {
		return nil, nil
	}
	alarmed := make(map[string]bool, len(st.AWS.AlarmedMetrics))
	for _, m := range st.AWS.AlarmedMetrics {
		alarmed[m] = true
	}
	now := time.Now().UTC()
	account := st.AWS.Account

	var out []findings.Finding
	for _, ctrl := range cisMonitoringControls {
		if monitoredAndAlarmed(st.AWS.LogMetricFilters, alarmed, ctrl) {
			continue
		}
		res := findings.Resource{
			ID: account + ":cis-" + ctrl.cis, Name: "CIS " + ctrl.cis, Type: "aws_account", Provider: "aws", Account: account,
		}
		desc := "No CloudWatch metric filter with an alarm covers " + ctrl.label + " (CIS " + ctrl.cis + ")."
		poc := "aws logs describe-metric-filters && aws cloudwatch describe-alarms  # verify coverage for: " + ctrl.label
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

// monitoredAndAlarmed reports whether some metric filter matches the control's
// signature and emits a metric that has an alarm.
func monitoredAndAlarmed(filters []state.LogMetricFilter, alarmed map[string]bool, ctrl monitoringControl) bool {
	for _, f := range filters {
		if !patternMatches(f.Pattern, ctrl) {
			continue
		}
		for _, m := range f.MetricNames {
			if alarmed[m] {
				return true
			}
		}
	}
	return false
}

// patternMatches reports whether a filter pattern satisfies a control's tokens:
// every "all" token present, or (when all is empty) at least one "any" token.
func patternMatches(pattern string, ctrl monitoringControl) bool {
	if len(ctrl.all) > 0 {
		for _, tok := range ctrl.all {
			if !strings.Contains(pattern, tok) {
				return false
			}
		}
		return true
	}
	for _, tok := range ctrl.any {
		if strings.Contains(pattern, tok) {
			return true
		}
	}
	return false
}
