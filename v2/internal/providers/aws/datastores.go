package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(datastoreCollector{}) }

type datastoreCollector struct{}

func (datastoreCollector) Name() string { return "aws:datastores" }

// Collect gathers encryption/backup posture for EFS file systems, ElastiCache
// (Redis) replication groups, and DynamoDB tables per region. Per-region/resource
// failures are tolerated.
func (datastoreCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		collectEFS(sc, region, st)
		collectElasticache(sc, region, st)
		collectDynamoDB(sc, region, st)
	}
	return nil
}

func collectEFS(sc *engine.ScanContext, region string, st *state.State) {
	client := efs.NewFromConfig(sc.AWS, func(o *efs.Options) { o.Region = region })
	var marker *string
	for {
		out, err := client.DescribeFileSystems(sc.Ctx, &efs.DescribeFileSystemsInput{Marker: marker})
		if err != nil {
			return
		}
		for _, fsd := range out.FileSystems {
			st.AddEFSFileSystem(state.EFSFileSystem{
				ID: awssdk.ToString(fsd.FileSystemId), Region: region, Encrypted: awssdk.ToBool(fsd.Encrypted),
			})
		}
		if out.NextMarker == nil {
			return
		}
		marker = out.NextMarker
	}
}

func collectElasticache(sc *engine.ScanContext, region string, st *state.State) {
	client := elasticache.NewFromConfig(sc.AWS, func(o *elasticache.Options) { o.Region = region })
	p := elasticache.NewDescribeReplicationGroupsPaginator(client, &elasticache.DescribeReplicationGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, rg := range page.ReplicationGroups {
			st.AddElasticacheGroup(state.ElasticacheGroup{
				ID:                 awssdk.ToString(rg.ReplicationGroupId),
				Region:             region,
				AtRestEncrypted:    awssdk.ToBool(rg.AtRestEncryptionEnabled),
				InTransitEncrypted: awssdk.ToBool(rg.TransitEncryptionEnabled),
			})
		}
	}
}

func collectDynamoDB(sc *engine.ScanContext, region string, st *state.State) {
	client := dynamodb.NewFromConfig(sc.AWS, func(o *dynamodb.Options) { o.Region = region })
	p := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, name := range page.TableNames {
			st.AddDynamoDBTable(state.DynamoDBTable{Name: name, Region: region, PITREnabled: dynamoPITR(sc, client, name)})
		}
	}
}

// dynamoPITR reports whether point-in-time recovery is enabled for a table.
// A read failure returns false (the check skips when nothing was collected, not
// per-table) — but here a denied DescribeContinuousBackups simply omits the
// table's PITR signal, which the check treats conservatively.
func dynamoPITR(sc *engine.ScanContext, client *dynamodb.Client, table string) bool {
	out, err := client.DescribeContinuousBackups(sc.Ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: awssdk.String(table)})
	if err != nil || out.ContinuousBackupsDescription == nil || out.ContinuousBackupsDescription.PointInTimeRecoveryDescription == nil {
		return false
	}
	return out.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbtypes.PointInTimeRecoveryStatusEnabled
}
