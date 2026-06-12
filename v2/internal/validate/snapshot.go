package validate

import (
	"context"
	"errors"
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
		"ec2:DescribeSnapshotAttribute(createVolumePermission)", "snapshot(s)",
		func(ctx context.Context, a findings.Affected) (bool, string, error) {
			c := env.EC2SnapshotAttr(a.Region)
			if c == nil {
				return false, "", errNoRegionClient
			}
			out, err := c.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
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
		"ec2:DescribeImageAttribute(launchPermission)", "image(s)",
		func(ctx context.Context, a findings.Affected) (bool, string, error) {
			c := env.EC2ImageAttr(a.Region)
			if c == nil {
				return false, "", errNoRegionClient
			}
			out, err := c.DescribeImageAttribute(ctx, &ec2.DescribeImageAttributeInput{
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
		"rds:DescribeDBSnapshotAttributes(restore)", "snapshot(s)",
		func(ctx context.Context, a findings.Affected) (bool, string, error) {
			c := env.RDSSnapshotAttr(a.Region)
			if c == nil {
				return false, "", errNoRegionClient
			}
			out, err := c.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
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

// errNoRegionClient is recorded for an affected item whose region has no
// read-only client (the Env capability closure returned nil). Such an item is
// undeterminable, not clean.
var errNoRegionClient = errors.New("no read-only client for region")

// maxValidateItems caps how many resources one aggregate validator probes in a
// single invocation. It bounds the burst of authenticated control-plane API
// calls a single finding can trigger (the validation pass is opt-in, but should
// not hammer the API). When an aggregate finding lists more, the overflow is
// reported explicitly in the evidence — never silently dropped — and the
// operator can re-run with a larger --timeout or a narrower scope.
const maxValidateItems = 200

// confirmPublicShares runs probe over every wantType-typed affected item and
// folds the per-item results into a single authenticated-vantage evidence
// record. probe reports whether the item is public, a human-readable detail for
// the non-error case, and any describe error.
//
// Verdict: any item provably public → confirmed (the exposure is real); nothing
// confirmed but at least one item unreadable or unprobed → blocked
// (undeterminable); every in-scope item read and none public → unconfirmed.
// Crucially, the evidence always carries a confirmed/errored/clean/probed
// summary, so a confirmed verdict from a partial run (some items errored or hit
// the cap/timeout) is never mistaken for a complete all-clear — the operator
// can see that other in-scope resources went unconfirmed.
func confirmPublicShares(
	ctx context.Context,
	items []findings.Affected,
	wantType, apiDesc, noun string,
	probe func(context.Context, findings.Affected) (bool, string, error),
) (*findings.Evidence, error) {
	var confirmed, errored, checked, inScope int
	truncated := false
	stopped := false
	details := make([]string, 0, len(items))

	for _, a := range items {
		if a.Type != wantType || a.ID == "" {
			continue
		}
		inScope++ // count every in-scope item, even past the probing cut-off
		if stopped {
			truncated = true
			continue
		}
		if checked >= maxValidateItems || ctx.Err() != nil {
			stopped, truncated = true, true
			continue
		}
		if a.Region == "" {
			// A resource we cannot target (missing region) is undeterminable, not
			// clean — count it as an error so it never reads as "not public".
			checked++
			errored++
			details = append(details, a.ID+": missing region, cannot validate")
			continue
		}
		checked++
		public, detail, err := probe(ctx, a)
		switch {
		case err != nil:
			errored++
			details = append(details, a.ID+": describe error: "+err.Error())
		case public:
			confirmed++
			details = append(details, detail)
		default:
			details = append(details, detail)
		}
	}

	if inScope == 0 {
		return nil, nil // nothing in scope for this validator
	}

	clean := checked - confirmed - errored
	summary := fmt.Sprintf("confirmed=%d errored=%d clean=%d probed=%d/%d",
		confirmed, errored, clean, checked, inScope)
	if truncated {
		summary += fmt.Sprintf("; %d in-scope item(s) not probed (cap %d or timeout) — re-run with a larger --timeout or narrower scope",
			inScope-checked, maxValidateItems)
	}

	ev := &findings.Evidence{
		Vantage:    findings.VantageAuthenticated,
		Request:    fmt.Sprintf("%s over %d of %d %s  (read-only)", apiDesc, checked, inScope, noun),
		Response:   truncateJoin(append([]string{summary}, details...)),
		CapturedAt: time.Now().UTC(),
	}
	switch {
	case confirmed > 0:
		ev.Verdict = VerdictConfirmed
	case errored > 0 || truncated:
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
