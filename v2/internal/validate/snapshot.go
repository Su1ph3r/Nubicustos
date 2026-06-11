package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func init() { Register(&ebsSnapshotPublic{}) }

// EC2SnapshotAttrAPI is the read-only EC2 surface the public-EBS-snapshot
// validator needs: a single DescribeSnapshotAttribute call. The AWS SDK's
// *ec2.Client satisfies it; tests provide a fake.
type EC2SnapshotAttrAPI interface {
	DescribeSnapshotAttribute(context.Context, *ec2.DescribeSnapshotAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error)
}

// ebsSnapshotPublic confirms a "publicly shared EBS snapshot" finding from the
// authenticated vantage: using the scan credentials, it reads each snapshot's
// createVolumePermission attribute and checks for an explicit grant to the
// "all" group. That grant is the exact mechanism that makes a snapshot world-
// restorable, so its presence is a direct, current proof of the exposure (and
// catches the case where it was remediated between the scan and validation).
//
// It is read-only: a single Describe* call per snapshot, no modify/reset, blast
// radius none. The finding is account-scoped and aggregate (one finding listing
// many snapshots in its Affected set), so this emits one evidence record
// summarizing the snapshots it could confirm.
type ebsSnapshotPublic struct{}

func (ebsSnapshotPublic) CheckID() string     { return "aws_ebs_snapshot_public" }
func (ebsSnapshotPublic) BlastRadius() string { return BlastRadiusNone }

func (ebsSnapshotPublic) Validate(ctx context.Context, env Env, f findings.Finding) (*findings.Evidence, error) {
	if env.EC2SnapshotAttr == nil {
		return nil, nil // no authenticated session available (e.g. offline validate) — skip
	}
	if len(f.Affected) == 0 {
		return nil, nil
	}

	var confirmed, checked int
	var blockedErr error
	details := make([]string, 0, len(f.Affected))

	for _, a := range f.Affected {
		if a.Type != "ebs_snapshot" || a.ID == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			blockedErr = err // ran out of the per-action budget; report what we have
			break
		}
		client := env.EC2SnapshotAttr(a.Region)
		if client == nil {
			continue
		}
		checked++
		out, err := client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
			SnapshotId: aws.String(a.ID),
			Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
		})
		if err != nil {
			blockedErr = err
			details = append(details, fmt.Sprintf("%s: describe error: %s", a.ID, err.Error()))
			continue
		}
		if hasPublicCreateVolumePermission(out.CreateVolumePermissions) {
			confirmed++
			details = append(details, a.ID+": createVolumePermission grants Group=all")
		} else {
			details = append(details, a.ID+": no public createVolumePermission grant")
		}
	}

	if checked == 0 {
		return nil, nil // nothing in scope for this validator
	}

	ev := &findings.Evidence{
		Vantage:    findings.VantageAuthenticated,
		Request:    fmt.Sprintf("ec2:DescribeSnapshotAttribute(createVolumePermission) over %d snapshot(s)  (read-only)", checked),
		Response:   truncateJoin(details),
		CapturedAt: time.Now().UTC(),
	}
	switch {
	case confirmed > 0:
		ev.Verdict = VerdictConfirmed
	case blockedErr != nil:
		// Could not read the attribute (AccessDenied / cancelled) and confirmed
		// none — we could not determine the current state.
		ev.Verdict = VerdictBlocked
	default:
		// Read every snapshot's attribute and none is public anymore.
		ev.Verdict = VerdictUnconfirmed
	}
	return ev, nil
}

// hasPublicCreateVolumePermission reports whether the permission set grants the
// "all" group (world-restorable).
func hasPublicCreateVolumePermission(perms []ec2types.CreateVolumePermission) bool {
	for _, p := range perms {
		if p.Group == ec2types.PermissionGroupAll {
			return true
		}
	}
	return false
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
