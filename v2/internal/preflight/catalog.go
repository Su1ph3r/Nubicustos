// Package preflight answers, for a given credential, "does this identity have
// the access each scanning tool needs?" — before a scan is run. It verifies the
// required IAM actions per tool (Nubicustos's own native checks plus optional
// external tools like Prowler and ScoutSuite) and produces a client-ready
// report of exactly what is missing and an attachable least-privilege policy to
// grant it.
//
// Verification is read-only and leads with IAM policy simulation
// (iam:SimulatePrincipalPolicy) for exact per-action allow/deny, cross-checked
// by a thin live read-probe that catches denials simulation cannot see (SCPs,
// session policies) and covers the case where simulation itself is denied.
package preflight

// Tool is one scanning tool's access requirements on a provider.
type Tool struct {
	Key         string // stable id, e.g. "nubicustos", "prowler"
	Name        string // display name
	Description string
	// RequiredManagedPolicies are AWS managed policies that grant this tool's
	// access wholesale (recommended remediation), e.g. "SecurityAudit".
	RequiredManagedPolicies []string
	// RequiredActions is the set of IAM actions the tool needs. For Nubicustos
	// this is authoritative (derived from our collectors); for external tools it
	// is the documented required set (managed policies remain the simplest grant).
	RequiredActions []string
	// RemediationPolicyName names the generated inline policy of any missing actions.
	RemediationPolicyName string
}

// AWSManagedPolicyARN maps a managed-policy short name to its ARN.
var AWSManagedPolicyARN = map[string]string{
	"SecurityAudit":  "arn:aws:iam::aws:policy/SecurityAudit",
	"ReadOnlyAccess": "arn:aws:iam::aws:policy/ReadOnlyAccess",
	"ViewOnlyAccess": "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
}

// nubicustosAWSActions is the authoritative set of AWS API actions Nubicustos's
// own native AWS collectors, checks, and active validators invoke. Derived from
// the read-only Describe/List/Get calls in internal/providers/aws,
// internal/checks/aws, and internal/validate. Keep in sync when a collector adds
// an API call (the registration tests guard the check set; this list guards the
// access the scan needs to run).
var nubicustosAWSActions = []string{
	// identity / scope
	"sts:GetCallerIdentity",
	"ec2:DescribeRegions",
	// S3
	"s3:ListAllMyBuckets",
	"s3:GetBucketAcl",
	"s3:GetBucketLocation",
	"s3:GetBucketPolicyStatus",
	"s3:GetBucketPublicAccessBlock",
	// IAM
	"iam:ListUsers",
	"iam:ListRoles",
	"iam:ListAccessKeys",
	"iam:ListMFADevices",
	"iam:ListAttachedUserPolicies",
	"iam:ListAttachedRolePolicies",
	"iam:ListUserPolicies",
	"iam:ListRolePolicies",
	"iam:GetUserPolicy",
	"iam:GetRolePolicy",
	"iam:GetPolicy",
	"iam:GetPolicyVersion",
	"iam:GetAccountPasswordPolicy",
	"iam:GetAccountSummary",
	"iam:GetLoginProfile",
	"iam:GetInstanceProfile",
	// EC2 / VPC
	"ec2:DescribeInstances",
	"ec2:DescribeSecurityGroups",
	"ec2:DescribeVolumes",
	"ec2:DescribeSnapshots",
	"ec2:DescribeSnapshotAttribute",
	"ec2:DescribeImages",
	"ec2:DescribeImageAttribute",
	"ec2:DescribeVpcs",
	"ec2:DescribeFlowLogs",
	"ec2:DescribeSubnets",
	"ec2:DescribeRouteTables",
	"ec2:GetEbsEncryptionByDefault",
	// RDS
	"rds:DescribeDBInstances",
	"rds:DescribeDBSnapshots",
	"rds:DescribeDBSnapshotAttributes",
	// CloudTrail
	"cloudtrail:DescribeTrails",
	"cloudtrail:GetTrailStatus",
	// Config
	"config:DescribeConfigurationRecorders",
	"config:DescribeConfigurationRecorderStatus",
	// GuardDuty
	"guardduty:ListDetectors",
	"guardduty:GetDetector",
	// KMS
	"kms:ListKeys",
	"kms:DescribeKey",
	"kms:GetKeyRotationStatus",
	// Secrets Manager
	"secretsmanager:ListSecrets",
	// ELBv2
	"elasticloadbalancing:DescribeLoadBalancers",
	"elasticloadbalancing:DescribeListeners",
	"elasticloadbalancing:DescribeLoadBalancerAttributes",
	// ACM
	"acm:ListCertificates",
	"acm:DescribeCertificate",
	// Route 53 (dangling-DNS / subdomain-takeover collector — runs every AWS scan)
	"route53:ListHostedZones",
	"route53:ListResourceRecordSets",
	// Cloud-side secrets detection (§9.2 — Lambda env, EC2 userdata, SSM plaintext)
	"lambda:ListFunctions",
	// Lambda public-exposure posture (function URL + resource policy)
	"lambda:GetFunctionUrlConfig",
	"lambda:GetPolicy",
	// SNS / SQS public resource-policy posture
	"sns:ListTopics",
	"sns:GetTopicAttributes",
	"sqs:ListQueues",
	"sqs:GetQueueAttributes",
	// Redshift posture
	"redshift:DescribeClusters",
	// ECR posture (scan-on-push + repository policy)
	"ecr:DescribeRepositories",
	"ecr:GetRepositoryPolicy",
	"ec2:DescribeInstanceAttribute",
	"ssm:DescribeParameters",
	"ssm:GetParameters",
}

// nubicustosAWSOrgActions are additionally required only for an org-wide scan
// (`scan --org` / `--accounts` / `--ou`, §9.4): enumerate the organization from
// the management/delegated-admin account and assume the org access role into each
// member. They are intentionally kept out of the always-required set above so a
// single-account preflight does not report them as missing — the common path
// never calls Organizations. The SecurityAudit managed policy does not grant
// these; an org operator needs them granted explicitly (e.g. AWSOrganizationsReadOnlyAccess
// plus sts:AssumeRole on the member-account role).
var nubicustosAWSOrgActions = []string{
	"organizations:ListAccounts",
	"organizations:ListAccountsForParent",
	"organizations:ListOrganizationalUnitsForParent",
	"sts:AssumeRole",
}

// nubicustosAWSAssumeActions is the org-side access an *explicit* --accounts
// preflight needs from the base identity: enumeration is skipped (the operator
// supplied the account ids), but each member is still reached by assuming the
// org role. So sts:AssumeRole is required while the organizations:* reads are
// not — flagging those as missing would be a false partial for this mode.
var nubicustosAWSAssumeActions = []string{"sts:AssumeRole"}

// AWSTools is the requirement catalog for AWS scanning tools. The Nubicustos
// entry is authoritative; the external entries are the documented required
// access (ported from the v1 catalog) — for those, attaching the managed
// policies is the simplest complete grant and the action list is the set we
// verify directly.
var AWSTools = []Tool{
	{
		Key: "nubicustos", Name: "Nubicustos (native checks)",
		Description:             "The built-in read-only cloud-posture engine + active validation",
		RequiredManagedPolicies: []string{"SecurityAudit"},
		RequiredActions:         nubicustosAWSActions,
		RemediationPolicyName:   "NubicustosReadOnlyPolicy",
	},
	{
		Key: "prowler", Name: "Prowler",
		Description:             "AWS security posture management",
		RequiredManagedPolicies: []string{"SecurityAudit", "ViewOnlyAccess"},
		RequiredActions: []string{
			"account:GetAlternateContact",
			"appstream:DescribeFleets",
			"backup:ListBackupPlans",
			"cloudtrail:GetInsightSelectors",
			"cognito-idp:GetUserPoolMfaConfig",
			"ds:DescribeDirectories",
			"dynamodb:GetResourcePolicy",
			"ec2:GetEbsEncryptionByDefault",
			"ec2:GetSnapshotBlockPublicAccessState",
			"ecr:GetRegistryScanningConfiguration",
			"elasticfilesystem:DescribeBackupPolicy",
			"glue:GetSecurityConfigurations",
			"lambda:GetFunctionUrlConfig",
			"logs:FilterLogEvents",
			"macie2:GetMacieSession",
			"s3:GetAccountPublicAccessBlock",
			"shield:GetSubscriptionState",
			"ssm:GetDocument",
			"support:DescribeTrustedAdvisorChecks",
			"wellarchitected:ListWorkloads",
		},
		RemediationPolicyName: "ProwlerAdditionsPolicy",
	},
	{
		Key: "scoutsuite", Name: "ScoutSuite",
		Description:             "Multi-cloud security auditing",
		RequiredManagedPolicies: []string{"ReadOnlyAccess", "SecurityAudit"},
		RequiredActions: []string{
			"s3:GetBucketPublicAccessBlock",
			"s3:GetBucketAcl",
			"s3:GetBucketPolicy",
			"ec2:DescribeInstances",
			"ec2:DescribeSecurityGroups",
			"iam:ListUsers",
			"iam:ListRoles",
			"iam:GetAccountPasswordPolicy",
			"cloudtrail:DescribeTrails",
			"rds:DescribeDBInstances",
		},
		RemediationPolicyName: "ScoutSuiteReadOnlyPolicy",
	},
	{
		Key: "cloudsploit", Name: "CloudSploit",
		Description:             "Cloud security posture management",
		RequiredManagedPolicies: []string{"SecurityAudit"},
		RequiredActions: []string{
			"ec2:DescribeInstances",
			"ec2:DescribeSecurityGroups",
			"s3:ListAllMyBuckets",
			"iam:ListUsers",
			"cloudtrail:DescribeTrails",
		},
		RemediationPolicyName: "CloudSploitReadOnlyPolicy",
	},
}

// AWSToolByKey returns the catalog entry for key (ok=false if unknown).
func AWSToolByKey(key string) (Tool, bool) {
	for _, t := range AWSTools {
		if t.Key == key {
			return t, true
		}
	}
	return Tool{}, false
}

// AWSToolWithOrg returns t with the org-wide-scan actions appended when org is
// true and t is the native Nubicustos tool; otherwise t is returned unchanged.
// `preflight --org` uses it so an operator can confirm Organizations enumeration
// and member assume-role access (§9.4) before launching an estate-wide scan,
// without those actions polluting the common single-account check.
func AWSToolWithOrg(t Tool, org bool) Tool {
	if !org || t.Key != "nubicustos" {
		return t
	}
	return appendActions(t, nubicustosAWSOrgActions)
}

// AWSToolWithMemberAssume returns the native tool with only sts:AssumeRole
// appended — the base-identity requirement for an explicit --accounts estate
// preflight, where Organizations enumeration is skipped but each member is still
// reached by assuming the org role. Non-native tools are returned unchanged.
func AWSToolWithMemberAssume(t Tool) Tool {
	if t.Key != "nubicustos" {
		return t
	}
	return appendActions(t, nubicustosAWSAssumeActions)
}

// appendActions returns t with extra actions appended, never mutating the shared
// base slice (it allocates a fresh backing array).
func appendActions(t Tool, extra []string) Tool {
	merged := make([]string, 0, len(t.RequiredActions)+len(extra))
	merged = append(merged, t.RequiredActions...)
	merged = append(merged, extra...)
	t.RequiredActions = merged
	return t
}
