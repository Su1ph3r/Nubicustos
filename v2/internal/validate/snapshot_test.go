package validate

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// fakeSnapAttr returns canned createVolumePermission output keyed by snapshot id,
// or an error for ids in errIDs.
type fakeSnapAttr struct {
	public map[string]bool   // snapshot id -> grants Group=all
	errIDs map[string]string // snapshot id -> error message
	calls  int
}

func (f *fakeSnapAttr) DescribeSnapshotAttribute(_ context.Context, in *ec2.DescribeSnapshotAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error) {
	f.calls++
	id := aws.ToString(in.SnapshotId)
	if msg, bad := f.errIDs[id]; bad {
		return nil, errors.New(msg)
	}
	out := &ec2.DescribeSnapshotAttributeOutput{SnapshotId: in.SnapshotId}
	if f.public[id] {
		out.CreateVolumePermissions = []ec2types.CreateVolumePermission{{Group: ec2types.PermissionGroupAll}}
	} else {
		// A non-public snapshot may still grant a specific account.
		out.CreateVolumePermissions = []ec2types.CreateVolumePermission{{UserId: aws.String("123456789012")}}
	}
	return out, nil
}

func envWith(f *fakeSnapAttr) Env {
	return Env{EC2SnapshotAttr: func(string) EC2SnapshotAttrAPI { return f }}
}

func ebsFinding(items ...findings.Affected) findings.Finding {
	return findings.Finding{CheckID: "aws_ebs_snapshot_public", Affected: items}
}

func snap(id string) findings.Affected {
	return findings.Affected{Type: "ebs_snapshot", ID: id, Region: "us-east-1"}
}

func TestEBSSnapshotConfirmedWhenPublic(t *testing.T) {
	fake := &fakeSnapAttr{public: map[string]bool{"snap-aaa": true, "snap-bbb": false}}
	v := ebsSnapshotPublic{}
	ev, err := v.Validate(context.Background(), envWith(fake), ebsFinding(snap("snap-aaa"), snap("snap-bbb")))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("a public snapshot should confirm, got %+v", ev)
	}
	if ev.Vantage != findings.VantageAuthenticated {
		t.Fatalf("snapshot validation uses authenticated vantage, got %s", ev.Vantage)
	}
	if fake.calls != 2 {
		t.Fatalf("expected one describe per snapshot, got %d", fake.calls)
	}
}

func TestEBSSnapshotUnconfirmedWhenNotPublic(t *testing.T) {
	fake := &fakeSnapAttr{public: map[string]bool{"snap-aaa": false}}
	v := ebsSnapshotPublic{}
	ev, err := v.Validate(context.Background(), envWith(fake), ebsFinding(snap("snap-aaa")))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictUnconfirmed {
		t.Fatalf("a snapshot no longer public should be unconfirmed, got %+v", ev)
	}
}

func TestEBSSnapshotBlockedWhenDescribeDenied(t *testing.T) {
	fake := &fakeSnapAttr{errIDs: map[string]string{"snap-aaa": "AccessDenied"}}
	v := ebsSnapshotPublic{}
	ev, err := v.Validate(context.Background(), envWith(fake), ebsFinding(snap("snap-aaa")))
	if err != nil {
		t.Fatalf("a describe error must be captured as evidence, not returned: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictBlocked {
		t.Fatalf("an undeterminable read should be blocked, got %+v", ev)
	}
}

func TestEBSSnapshotConfirmedDespitePartialError(t *testing.T) {
	// One snapshot errors, another is genuinely public → still confirmed.
	fake := &fakeSnapAttr{
		public: map[string]bool{"snap-ok": true},
		errIDs: map[string]string{"snap-err": "Throttling"},
	}
	v := ebsSnapshotPublic{}
	ev, _ := v.Validate(context.Background(), envWith(fake), ebsFinding(snap("snap-err"), snap("snap-ok")))
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("a confirmed public snapshot should win over a partial error, got %+v", ev)
	}
}

func TestEBSSnapshotSkippedWithoutSession(t *testing.T) {
	v := ebsSnapshotPublic{}
	ev, err := v.Validate(context.Background(), Env{}, ebsFinding(snap("snap-aaa")))
	if err != nil || ev != nil {
		t.Fatalf("without an authenticated session the validator must skip, got ev=%+v err=%v", ev, err)
	}
}

func TestEBSSnapshotNoAffectedNoOp(t *testing.T) {
	fake := &fakeSnapAttr{}
	v := ebsSnapshotPublic{}
	ev, err := v.Validate(context.Background(), envWith(fake), ebsFinding())
	if err != nil || ev != nil {
		t.Fatalf("a finding with no affected snapshots is a no-op, got ev=%+v err=%v", ev, err)
	}
	if fake.calls != 0 {
		t.Fatalf("no describe calls expected, got %d", fake.calls)
	}
}

func TestEBSSnapshotIgnoresNonSnapshotAffected(t *testing.T) {
	fake := &fakeSnapAttr{public: map[string]bool{"snap-aaa": true}}
	v := ebsSnapshotPublic{}
	mixed := ebsFinding(
		findings.Affected{Type: "region", ID: "us-west-2"}, // unrelated affected item
		snap("snap-aaa"),
	)
	ev, _ := v.Validate(context.Background(), envWith(fake), mixed)
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("non-snapshot affected items must be ignored, got %+v", ev)
	}
	if fake.calls != 1 {
		t.Fatalf("only the snapshot item should be described, got %d calls", fake.calls)
	}
}

func TestEBSSnapshotContractMetadata(t *testing.T) {
	v := ebsSnapshotPublic{}
	if v.CheckID() != "aws_ebs_snapshot_public" {
		t.Fatalf("unexpected check id %q", v.CheckID())
	}
	if v.BlastRadius() != BlastRadiusNone {
		t.Fatalf("snapshot validator must declare blast radius none, got %q", v.BlastRadius())
	}
}
