package validate

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
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
