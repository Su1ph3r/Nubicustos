package validate

import (
	"context"
	"errors"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"

	"github.com/Su1ph3r/nubicustos/internal/secrets"
)

// NewAWSEnv builds the authenticated-vantage capabilities the validation pass
// needs from an AWS session: read-only, region-bound EC2/RDS describe clients
// for the public-snapshot and AMI validators. Shared by the inline scan
// --validate path, the standalone validate command, and the web scan runner.
func NewAWSEnv(cfg awssdk.Config) Env {
	return Env{
		EC2SnapshotAttr: func(region string) EC2SnapshotAttrAPI {
			return ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })
		},
		EC2ImageAttr: func(region string) EC2ImageAttrAPI {
			return ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })
		},
		RDSSnapshotAttr: func(region string) RDSSnapshotAttrAPI {
			return rds.NewFromConfig(cfg, func(o *rds.Options) { o.Region = region })
		},
	}
}

// stsKeyProber confirms captured AWS credentials with sts:GetCallerIdentity.
// Each probe uses ONLY the captured static credential — never the scan session —
// so the verdict reflects that specific key's liveness. Retries are disabled so a
// rejected (invalid/expired) key returns immediately rather than backing off.
type stsKeyProber struct{}

// NewAWSKeyProber returns the SDK-backed prober for captured-secret liveness
// validation. It needs no scan session: it builds a throwaway client per key
// from the key's own static credentials.
func NewAWSKeyProber() AWSKeyProber { return stsKeyProber{} }

func (stsKeyProber) WhoAmI(ctx context.Context, cred secrets.AWSKeyCredential) (WhoAmIResult, error) {
	region := cred.Region
	if region == "" {
		region = "us-east-1" // STS is global; any region resolves the endpoint
	}
	cfg := awssdk.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken),
		Retryer:     func() awssdk.Retryer { return retry.AddWithMaxAttempts(retry.NewStandard(), 1) },
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// An authentication rejection is a definitive "not live" verdict, not a
		// failed probe; only genuine transport/timeout errors are reported as
		// blocked (non-nil error) to the validator.
		if isAuthRejection(err) {
			return WhoAmIResult{Live: false}, nil
		}
		return WhoAmIResult{}, err
	}
	return WhoAmIResult{
		ARN:     awssdk.ToString(out.Arn),
		Account: awssdk.ToString(out.Account),
		Live:    true,
	}, nil
}

// isAuthRejection reports whether err is AWS authoritatively rejecting the
// credential (expired/invalid/disabled) rather than a transport failure.
func isAuthRejection(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken",
		"AccessDenied", "InvalidAccessKeyId", "TokenRefreshRequired", "AuthFailure":
		return true
	}
	return false
}
