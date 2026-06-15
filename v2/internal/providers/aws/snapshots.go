package aws

import (
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&snapshotCollector{}) }

type snapshotCollector struct{}

func (snapshotCollector) Name() string { return "aws:snapshots" }

// Collect finds publicly shared data exports across regions: EBS snapshots,
// AMIs, and RDS snapshots that the account owns and has shared with everyone.
func (snapshotCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		ec2c := ec2.NewFromConfig(sc.AWS, func(o *ec2.Options) { o.Region = region })
		collectPublicEBSSnapshots(sc, ec2c, region, st)
		collectPublicAMIs(sc, ec2c, region, st)

		rdsc := rds.NewFromConfig(sc.AWS, func(o *rds.Options) { o.Region = region })
		collectPublicRDSSnapshots(sc, rdsc, region, st)
	}
	return nil
}

// collectPublicEBSSnapshots lists snapshots the account owns that are restorable
// by all (i.e. public). Filtering owner=self keeps the result to our snapshots.
func collectPublicEBSSnapshots(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	pager := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds:            []string{"self"},
		RestorableByUserIds: []string{"all"},
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, s := range page.Snapshots {
			id := awssdk.ToString(s.SnapshotId)
			st.AddPublicEBSSnapshot(state.ResourceRef{
				ID:     id,
				Region: region,
				ARN:    fmt.Sprintf("arn:aws:ec2:%s::snapshot/%s", region, id),
			})
		}
	}
}

// collectPublicAMIs lists self-owned images flagged public.
func collectPublicAMIs(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	out, err := client.DescribeImages(sc.Ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		return
	}
	for _, img := range out.Images {
		if !awssdk.ToBool(img.Public) {
			continue
		}
		id := awssdk.ToString(img.ImageId)
		st.AddPublicAMI(state.ResourceRef{
			ID:     id,
			Region: region,
			ARN:    fmt.Sprintf("arn:aws:ec2:%s::image/%s", region, id),
		})
	}
}

// collectPublicRDSSnapshots checks manual RDS snapshots for a "restore"
// attribute granting access to "all" (public).
func collectPublicRDSSnapshots(sc *engine.ScanContext, client *rds.Client, region string, st *state.State) {
	pager := rds.NewDescribeDBSnapshotsPaginator(client, &rds.DescribeDBSnapshotsInput{
		SnapshotType: awssdk.String("manual"),
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, snap := range page.DBSnapshots {
			id := awssdk.ToString(snap.DBSnapshotIdentifier)
			attr, err := client.DescribeDBSnapshotAttributes(sc.Ctx, &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: &id,
			})
			if err != nil || attr.DBSnapshotAttributesResult == nil {
				continue
			}
			if rdsSnapshotIsPublic(attr.DBSnapshotAttributesResult.DBSnapshotAttributes) {
				st.AddPublicRDSSnapshot(state.ResourceRef{
					ID:     id,
					Region: region,
					ARN:    awssdk.ToString(snap.DBSnapshotArn),
				})
			}
		}
	}
}

// rdsSnapshotIsPublic reports whether the "restore" attribute grants "all".
func rdsSnapshotIsPublic(attrs []rdstypes.DBSnapshotAttribute) bool {
	for _, a := range attrs {
		if awssdk.ToString(a.AttributeName) != "restore" {
			continue
		}
		for _, v := range a.AttributeValues {
			if v == "all" {
				return true
			}
		}
	}
	return false
}
