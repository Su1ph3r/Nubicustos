package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&rdsCollector{}) }

type rdsCollector struct{}

func (rdsCollector) Name() string { return "aws:rds" }

// Collect gathers RDS instance posture (public access, encryption, backups,
// deletion protection) across every scanned region.
func (rdsCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := rds.NewFromConfig(sc.AWS, func(o *rds.Options) { o.Region = region })
		pager := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, db := range page.DBInstances {
				st.AddRDSInstance(state.RDSInstance{
					ID:                 awssdk.ToString(db.DBInstanceIdentifier),
					Region:             region,
					Engine:             awssdk.ToString(db.Engine),
					Public:             awssdk.ToBool(db.PubliclyAccessible),
					Encrypted:          awssdk.ToBool(db.StorageEncrypted),
					BackupRetention:    int(awssdk.ToInt32(db.BackupRetentionPeriod)),
					DeletionProtection: awssdk.ToBool(db.DeletionProtection),
				})
			}
		}
	}
	return nil
}
