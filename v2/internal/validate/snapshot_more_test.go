package validate

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// --- public AMI -------------------------------------------------------------

type fakeImageAttr struct {
	public map[string]bool
	err    error
	calls  int
}

func (f *fakeImageAttr) DescribeImageAttribute(_ context.Context, in *ec2.DescribeImageAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeImageAttributeOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := &ec2.DescribeImageAttributeOutput{ImageId: in.ImageId}
	if f.public[aws.ToString(in.ImageId)] {
		out.LaunchPermissions = []ec2types.LaunchPermission{{Group: ec2types.PermissionGroupAll}}
	} else {
		out.LaunchPermissions = []ec2types.LaunchPermission{{UserId: aws.String("123456789012")}}
	}
	return out, nil
}

func amiFinding(ids ...string) findings.Finding {
	items := make([]findings.Affected, len(ids))
	for i, id := range ids {
		items[i] = findings.Affected{Type: "ami", ID: id, Region: "us-east-1"}
	}
	return findings.Finding{CheckID: "aws_ami_public", Affected: items}
}

func TestAMIConfirmedWhenPublic(t *testing.T) {
	fake := &fakeImageAttr{public: map[string]bool{"ami-aaa": true}}
	env := Env{EC2ImageAttr: func(string) EC2ImageAttrAPI { return fake }}
	ev, err := amiPublic{}.Validate(context.Background(), env, amiFinding("ami-aaa"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed || ev.Vantage != findings.VantageAuthenticated {
		t.Fatalf("a public AMI should confirm (authenticated), got %+v", ev)
	}
}

func TestAMIUnconfirmedWhenNotPublic(t *testing.T) {
	fake := &fakeImageAttr{public: map[string]bool{"ami-aaa": false}}
	env := Env{EC2ImageAttr: func(string) EC2ImageAttrAPI { return fake }}
	ev, _ := amiPublic{}.Validate(context.Background(), env, amiFinding("ami-aaa"))
	if ev == nil || ev.Verdict != VerdictUnconfirmed {
		t.Fatalf("an AMI no longer public should be unconfirmed, got %+v", ev)
	}
}

func TestAMIBlockedOnError(t *testing.T) {
	fake := &fakeImageAttr{err: errors.New("AccessDenied")}
	env := Env{EC2ImageAttr: func(string) EC2ImageAttrAPI { return fake }}
	ev, err := amiPublic{}.Validate(context.Background(), env, amiFinding("ami-aaa"))
	if err != nil {
		t.Fatalf("describe error must be captured as evidence: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictBlocked {
		t.Fatalf("an undeterminable read should be blocked, got %+v", ev)
	}
}

func TestAMISkippedWithoutSession(t *testing.T) {
	ev, err := amiPublic{}.Validate(context.Background(), Env{}, amiFinding("ami-aaa"))
	if err != nil || ev != nil {
		t.Fatalf("without a session the AMI validator must skip, got ev=%+v err=%v", ev, err)
	}
}

func TestAMIContractMetadata(t *testing.T) {
	v := amiPublic{}
	if v.CheckID() != "aws_ami_public" || v.BlastRadius() != BlastRadiusNone {
		t.Fatalf("unexpected contract: id=%q blast=%q", v.CheckID(), v.BlastRadius())
	}
}

// --- public RDS snapshot ----------------------------------------------------

type fakeRDSSnapAttr struct {
	public map[string]bool
	err    error
	calls  int
}

func (f *fakeRDSSnapAttr) DescribeDBSnapshotAttributes(_ context.Context, in *rds.DescribeDBSnapshotAttributesInput, _ ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	values := []string{"123456789012"}
	if f.public[aws.ToString(in.DBSnapshotIdentifier)] {
		values = []string{"all"}
	}
	return &rds.DescribeDBSnapshotAttributesOutput{
		DBSnapshotAttributesResult: &rdstypes.DBSnapshotAttributesResult{
			DBSnapshotIdentifier: in.DBSnapshotIdentifier,
			DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
				{AttributeName: aws.String("restore"), AttributeValues: values},
			},
		},
	}, nil
}

func rdsSnapFinding(ids ...string) findings.Finding {
	items := make([]findings.Affected, len(ids))
	for i, id := range ids {
		items[i] = findings.Affected{Type: "rds_snapshot", ID: id, Region: "us-east-1"}
	}
	return findings.Finding{CheckID: "aws_rds_snapshot_public", Affected: items}
}

func TestRDSSnapshotConfirmedWhenPublic(t *testing.T) {
	fake := &fakeRDSSnapAttr{public: map[string]bool{"snap-db": true}}
	env := Env{RDSSnapshotAttr: func(string) RDSSnapshotAttrAPI { return fake }}
	ev, err := rdsSnapshotPublic{}.Validate(context.Background(), env, rdsSnapFinding("snap-db"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed || ev.Vantage != findings.VantageAuthenticated {
		t.Fatalf("a public RDS snapshot should confirm (authenticated), got %+v", ev)
	}
}

func TestRDSSnapshotUnconfirmedWhenNotPublic(t *testing.T) {
	fake := &fakeRDSSnapAttr{public: map[string]bool{"snap-db": false}}
	env := Env{RDSSnapshotAttr: func(string) RDSSnapshotAttrAPI { return fake }}
	ev, _ := rdsSnapshotPublic{}.Validate(context.Background(), env, rdsSnapFinding("snap-db"))
	if ev == nil || ev.Verdict != VerdictUnconfirmed {
		t.Fatalf("a private RDS snapshot should be unconfirmed, got %+v", ev)
	}
}

func TestRDSSnapshotSkippedWithoutSession(t *testing.T) {
	ev, err := rdsSnapshotPublic{}.Validate(context.Background(), Env{}, rdsSnapFinding("snap-db"))
	if err != nil || ev != nil {
		t.Fatalf("without a session the RDS-snapshot validator must skip, got ev=%+v err=%v", ev, err)
	}
}

func TestRDSSnapshotContractMetadata(t *testing.T) {
	v := rdsSnapshotPublic{}
	if v.CheckID() != "aws_rds_snapshot_public" || v.BlastRadius() != BlastRadiusNone {
		t.Fatalf("unexpected contract: id=%q blast=%q", v.CheckID(), v.BlastRadius())
	}
}
