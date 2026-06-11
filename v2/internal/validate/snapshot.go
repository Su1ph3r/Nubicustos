package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func init() {
	Register(ebsSnapshotPublic{})
	Register(amiPublic{})
	Register(rdsSnapshotPublic{})
}

// The public-export validators (EBS snapshot, AMI, RDS snapshot) all confirm an
// account-scoped aggregate finding from the authenticated vantage: using the
// scan credentials, they re-read the share attribute that actually grants the
// world access ("all" group / "all" value) for each affected resource. Reading
// the grant at validation time is a direct, current proof of the exposure and
// catches a resource remediated between the scan and validation. Each performs
// one read-only Describe* call per resource — no modify/reset — blast radius
// none.

// EC2SnapshotAttrAPI is the read-only EC2 surface the public-EBS-snapshot
// validator needs. The AWS SDK's *ec2.Client satisfies it; tests fake it.
type EC2SnapshotAttrAPI interface {
	DescribeSnapshotAttribute(context.Context, *ec2.DescribeSnapshotAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error)
}

// EC2ImageAttrAPI is the read-only EC2 surface the public-AMI validator needs.
type EC2ImageAttrAPI interface {
	DescribeImageAttribute(context.Context, *ec2.DescribeImageAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeImageAttributeOutput, error)
}

// RDSSnapshotAttrAPI is the read-only RDS surface the public-RDS-snapshot
// validator needs.
type RDSSnapshotAttrAPI interface {
	DescribeDBSnapshotAttributes(context.Context, *rds.DescribeDBSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error)
}

// --- public EBS snapshot ----------------------------------------------------

type ebsSnapshotPublic struct{}

func (ebsSnapshotPublic) CheckID() string     { return "aws_ebs_snapshot_public" }
func (ebsSnapshotPublic) BlastRadius() string { return BlastRadiusNone }

func (ebsSnapshotPublic) Validate(ctx context.Context, env Env, f findings.Finding) (*findings.Evidence, error) {
	if env.EC2SnapshotAttr == nil {
		return nil, nil // no authenticated session (e.g. offline validate) — skip
	}
	return confirmPublicShares(ctx, f.Affected, "ebs_snapshot",
		"ec2:DescribeSnapshotAttribute(createVolumePermission) over %d snapshot(s)  (read-only)",
		func(ctx context.Context, a findings.Affected) (bool, string, error) {
			out, err := env.EC2SnapshotAttr(a.Region).DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
				SnapshotId: aws.String(a.ID),
				Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
			})
			if err != nil {
				return false, "", err
			}
			for _, p := range out.CreateVolumePermissions {
				if p.Group == ec2types.PermissionGroupAll {
					return true, a.ID + ": createVolumePermission grants Group=all", nil
				}
			}
			return false, a.ID + ": no public createVolumePermission grant", nil
		})
}

// --- public AMI -------------------------------------------------------------

type amiPublic struct{}

func (amiPublic) CheckID() string     { return "aws_ami_public" }
func (amiPublic) BlastRadius() string { return BlastRadiusNone }

func (amiPublic) Validate(ctx context.Context, env Env, f findings.Finding) (*findings.Evidence, error) {
	if env.EC2ImageAttr == nil {
		return nil, nil
	}
	return confirmPublicShares(ctx, f.Affected, "ami",
		"ec2:DescribeImageAttribute(launchPermission) over %d image(s)  (read-only)",
		func(ctx context.Context, a findings.Affected) (bool, string, error) {
			out, err := env.EC2ImageAttr(a.Region).DescribeImageAttribute(ctx, &ec2.DescribeImageAttributeInput{
				ImageId:   aws.String(a.ID),
				Attribute: ec2types.ImageAttributeNameLaunchPermission,
			})
			if err != nil {
				return false, "", err
			}
			for _, p := range out.LaunchPermissions {
				if p.Group == ec2types.PermissionGroupAll {
					return true, a.ID + ": launchPermission grants Group=all", nil
				}
			}
			return false, a.ID + ": no public launchPermission grant", nil
		})
}

// --- public RDS snapshot ----------------------------------------------------

type rdsSnapshotPublic struct{}

func (rdsSnapshotPublic) CheckID() string     { return "aws_rds_snapshot_public" }
func (rdsSnapshotPublic) BlastRadius() string { return BlastRadiusNone }

func (rdsSnapshotPublic) Validate(ctx context.Context, env Env, f findings.Finding) (*findings.Evidence, error) {
	if env.RDSSnapshotAttr == nil {
		return nil, nil
	}
	return confirmPublicShares(ctx, f.Affected, "rds_snapshot",
		"rds:DescribeDBSnapshotAttributes(restore) over %d snapshot(s)  (read-only)",
		func(ctx context.Context, a findings.Affected) (bool, string, error) {
			out, err := env.RDSSnapshotAttr(a.Region).DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: aws.String(a.ID),
			})
			if err != nil {
				return false, "", err
			}
			if out.DBSnapshotAttributesResult != nil &&
				rdsRestoreGrantsAll(out.DBSnapshotAttributesResult.DBSnapshotAttributes) {
				return true, a.ID + ": restore attribute grants 'all'", nil
			}
			return false, a.ID + ": restore attribute does not grant 'all'", nil
		})
}

// rdsRestoreGrantsAll reports whether the "restore" attribute lists "all".
func rdsRestoreGrantsAll(attrs []rdstypes.DBSnapshotAttribute) bool {
	for _, at := range attrs {
		if aws.ToString(at.AttributeName) != "restore" {
			continue
		}
		for _, v := range at.AttributeValues {
			if v == "all" {
				return true
			}
		}
	}
	return false
}

// --- shared aggregate-confirmation helper -----------------------------------

// confirmPublicShares runs probe over every wantType-typed affected item and
// folds the per-item results into a single authenticated-vantage evidence
// record: any item confirmed public → confirmed; an undeterminable read (error)
// with nothing confirmed → blocked; every item read and none public →
// unconfirmed. It returns nil when no item is in scope. probe returns whether
// the item is public, a human-readable detail for the non-error case, and any
// describe error. reqFmt is the request summary, formatted with the probed count.
func confirmPublicShares(
	ctx context.Context,
	items []findings.Affected,
	wantType, reqFmt string,
	probe func(context.Context, findings.Affected) (bool, string, error),
) (*findings.Evidence, error) {
	var confirmed, checked int
	var blockedErr error
	details := make([]string, 0, len(items))

	for _, a := range items {
		if a.Type != wantType || a.ID == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			blockedErr = err // out of the per-action budget; report what we have
			break
		}
		checked++
		public, detail, err := probe(ctx, a)
		if err != nil {
			blockedErr = err
			details = append(details, a.ID+": describe error: "+err.Error())
			continue
		}
		if public {
			confirmed++
		}
		details = append(details, detail)
	}

	if checked == 0 {
		return nil, nil // nothing in scope for this validator
	}

	ev := &findings.Evidence{
		Vantage:    findings.VantageAuthenticated,
		Request:    fmt.Sprintf(reqFmt, checked),
		Response:   truncateJoin(details),
		CapturedAt: time.Now().UTC(),
	}
	switch {
	case confirmed > 0:
		ev.Verdict = VerdictConfirmed
	case blockedErr != nil:
		ev.Verdict = VerdictBlocked
	default:
		ev.Verdict = VerdictUnconfirmed
	}
	return ev, nil
}

// truncateJoin joins detail lines into a single evidence string bounded by
// maxEvidenceBody so the captured evidence stays small.
func truncateJoin(lines []string) string {
	s := strings.Join(lines, "; ")
	if len(s) > maxEvidenceBody {
		s = s[:maxEvidenceBody] + "…(truncated)"
	}
	return s
}
