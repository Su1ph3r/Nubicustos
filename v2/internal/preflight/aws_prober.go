package preflight

import (
	"context"
	"errors"
	"net/http"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// NewAWSProber returns a Prober that confirms access by attempting one
// representative read call per service with the given session. Shared by the
// preflight command, the TUI access check, and the web preflight runner.
func NewAWSProber(cfg awssdk.Config) Prober { return &awsProber{cfg: cfg} }

// awsProber implements Prober with one representative read call per service.
// Access-denied (including via SCP) → denied; success → allowed; any other
// error or an action it does not probe → unknown (simulation covers it).
type awsProber struct {
	cfg awssdk.Config
}

func (p *awsProber) Probe(ctx context.Context, action string) Decision {
	var err error
	switch action {
	case "sts:GetCallerIdentity":
		_, err = sts.NewFromConfig(p.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	case "s3:ListAllMyBuckets":
		_, err = s3.NewFromConfig(p.cfg).ListBuckets(ctx, &s3.ListBucketsInput{})
	case "iam:ListUsers":
		_, err = iam.NewFromConfig(p.cfg).ListUsers(ctx, &iam.ListUsersInput{MaxItems: awssdk.Int32(1)})
	case "ec2:DescribeInstances":
		_, err = ec2.NewFromConfig(p.cfg).DescribeInstances(ctx, &ec2.DescribeInstancesInput{MaxResults: awssdk.Int32(5)})
	case "rds:DescribeDBInstances":
		_, err = rds.NewFromConfig(p.cfg).DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{MaxRecords: awssdk.Int32(20)})
	case "cloudtrail:DescribeTrails":
		_, err = cloudtrail.NewFromConfig(p.cfg).DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	case "kms:ListKeys":
		_, err = kms.NewFromConfig(p.cfg).ListKeys(ctx, &kms.ListKeysInput{Limit: awssdk.Int32(1)})
	case "guardduty:ListDetectors":
		_, err = guardduty.NewFromConfig(p.cfg).ListDetectors(ctx, &guardduty.ListDetectorsInput{MaxResults: awssdk.Int32(1)})
	case "acm:ListCertificates":
		_, err = acm.NewFromConfig(p.cfg).ListCertificates(ctx, &acm.ListCertificatesInput{MaxItems: awssdk.Int32(1)})
	case "secretsmanager:ListSecrets":
		_, err = secretsmanager.NewFromConfig(p.cfg).ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: awssdk.Int32(1)})
	case "elasticloadbalancing:DescribeLoadBalancers":
		_, err = elbv2.NewFromConfig(p.cfg).DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{PageSize: awssdk.Int32(1)})
	case "config:DescribeConfigurationRecorders":
		_, err = configservice.NewFromConfig(p.cfg).DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	default:
		return DecisionUnknown // not probed; simulation decides
	}
	switch {
	case err == nil:
		return DecisionAllowed
	case isAccessDenied(err):
		return DecisionDenied
	default:
		return DecisionUnknown // reachable-but-other-error; don't penalize
	}
}

// isAccessDenied reports whether err is an authorization failure. It matches on
// the error-code substring (so service-specific variants like
// AccessDeniedException or UnauthorizedOperation are all caught) and, as a
// backstop, on an HTTP 403 — so a denial under an unanticipated code is never
// silently read as a non-denial (which would defeat the SCP cross-check).
func isAccessDenied(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		code := strings.ToLower(ae.ErrorCode())
		for _, frag := range []string{"accessdenied", "unauthorized", "forbidden", "authorizationerror"} {
			if strings.Contains(code, frag) {
				return true
			}
		}
	}
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() == http.StatusForbidden {
		return true
	}
	return false
}
