package gcp

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func stateWith(g *state.GCP) *state.State {
	st := state.New()
	st.GCP = g
	return st
}

func evalCheck(t *testing.T, c engine.Check, st *state.State) []findings.Finding {
	t.Helper()
	fs, err := c.Evaluate(&engine.ScanContext{Provider: "gcp"}, st)
	if err != nil {
		t.Fatalf("%s: %v", c.Spec().ID, err)
	}
	return fs
}

func TestBucketPublicFlagged(t *testing.T) {
	st := stateWith(&state.GCP{Buckets: []state.GCSBucket{
		{Name: "open", Project: "p1", PublicIAM: true, UniformBucketLevelAccess: true, PublicAccessPrevention: "enforced"},
		{Name: "closed", Project: "p1", PublicIAM: false, UniformBucketLevelAccess: true, PublicAccessPrevention: "enforced"},
	}})
	fs := evalCheck(t, bucketPublic{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "open" || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("only the public bucket should be flagged high, got %+v", fs)
	}
}

func TestBucketUniformAndPAP(t *testing.T) {
	st := stateWith(&state.GCP{Buckets: []state.GCSBucket{
		{Name: "b", Project: "p1", UniformBucketLevelAccess: false, PublicAccessPrevention: "inherited"},
	}})
	if fs := evalCheck(t, bucketUniformAccess{}, st); len(fs) != 1 {
		t.Fatalf("expected uniform-access finding, got %d", len(fs))
	}
	if fs := evalCheck(t, bucketPublicAccessPrevention{}, st); len(fs) != 1 {
		t.Fatalf("expected public-access-prevention finding, got %d", len(fs))
	}
	// Enforced + uniform produces neither.
	clean := stateWith(&state.GCP{Buckets: []state.GCSBucket{
		{Name: "c", UniformBucketLevelAccess: true, PublicAccessPrevention: "enforced"},
	}})
	if fs := evalCheck(t, bucketPublicAccessPrevention{}, clean); len(fs) != 0 {
		t.Fatalf("enforced bucket should not be flagged, got %d", len(fs))
	}
}

func TestFirewallOpenIngress(t *testing.T) {
	st := stateWith(&state.GCP{Firewalls: []state.FirewallRule{
		{Name: "ssh-open", Project: "p1", Network: "default", Direction: "INGRESS",
			Allowed: []string{"tcp:22"}, SourceRanges: []string{"0.0.0.0/0"}},
		{Name: "internal", Project: "p1", Direction: "INGRESS",
			Allowed: []string{"tcp:22"}, SourceRanges: []string{"10.0.0.0/8"}},
		{Name: "disabled", Project: "p1", Direction: "INGRESS", Disabled: true,
			Allowed: []string{"tcp:22"}, SourceRanges: []string{"0.0.0.0/0"}},
		{Name: "egress", Project: "p1", Direction: "EGRESS",
			Allowed: []string{"all"}, SourceRanges: []string{"0.0.0.0/0"}},
	}})
	fs := evalCheck(t, firewallOpenIngress{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "ssh-open" {
		t.Fatalf("only the enabled internet-open ingress rule should be flagged, got %+v", fs)
	}
}

func TestFirewallAllProtocolOpen(t *testing.T) {
	st := stateWith(&state.GCP{Firewalls: []state.FirewallRule{
		{Name: "all", Project: "p1", Direction: "INGRESS", Allowed: []string{"all"}, SourceRanges: []string{"0.0.0.0/0"}},
	}})
	if fs := evalCheck(t, firewallOpenIngress{}, st); len(fs) != 1 {
		t.Fatalf("an all-protocol internet-open rule should be flagged, got %d", len(fs))
	}
}

func TestFirewallPortRange(t *testing.T) {
	st := stateWith(&state.GCP{Firewalls: []state.FirewallRule{
		{Name: "range", Project: "p1", Direction: "INGRESS", Allowed: []string{"tcp:3380-3400"}, SourceRanges: []string{"0.0.0.0/0"}},
	}})
	if fs := evalCheck(t, firewallOpenIngress{}, st); len(fs) != 1 {
		t.Fatalf("a range covering RDP/3389 should be flagged, got %d", len(fs))
	}
}

func TestFirewallBareUDPNotAllPorts(t *testing.T) {
	// A bare udp allow-all does not reach the TCP sensitive services, so it must
	// not be reported as exposing "all ports".
	st := stateWith(&state.GCP{Firewalls: []state.FirewallRule{
		{Name: "udp", Project: "p1", Direction: "INGRESS", Allowed: []string{"udp"}, SourceRanges: []string{"0.0.0.0/0"}},
	}})
	if fs := evalCheck(t, firewallOpenIngress{}, st); len(fs) != 0 {
		t.Fatalf("bare udp allow-all should not be flagged as sensitive-port exposure, got %d", len(fs))
	}
}

func TestFirewallUDPPortNotFlagged(t *testing.T) {
	// A UDP port spec covering 22 does not expose TCP SSH.
	st := stateWith(&state.GCP{Firewalls: []state.FirewallRule{
		{Name: "udp22", Project: "p1", Direction: "INGRESS", Allowed: []string{"udp:22"}, SourceRanges: []string{"0.0.0.0/0"}},
	}})
	if fs := evalCheck(t, firewallOpenIngress{}, st); len(fs) != 0 {
		t.Fatalf("udp:22 should not flag TCP SSH, got %d", len(fs))
	}
}

func TestIAMPublicMember(t *testing.T) {
	st := stateWith(&state.GCP{IAMBindings: []state.GCPIAMBinding{
		{Project: "p1", Role: "roles/viewer", Members: []string{"allUsers"}},
		{Project: "p1", Role: "roles/viewer", Members: []string{"user:alice@example.com"}},
	}})
	fs := evalCheck(t, iamPublicMember{}, st)
	if len(fs) != 1 {
		t.Fatalf("only the public binding should be flagged, got %d", len(fs))
	}
}

func TestIAMPrimitiveRole(t *testing.T) {
	st := stateWith(&state.GCP{IAMBindings: []state.GCPIAMBinding{
		{Project: "p1", Role: "roles/owner", Members: []string{"user:alice@example.com"}},
		{Project: "p1", Role: "roles/viewer", Members: []string{"user:bob@example.com"}},
	}})
	fs := evalCheck(t, iamPrimitiveRole{}, st)
	if len(fs) != 1 || fs[0].Resource.Name != "roles/owner" {
		t.Fatalf("only the primitive role should be flagged, got %+v", fs)
	}
}

func TestNilGCPStateNoPanic(t *testing.T) {
	st := state.New()
	st.GCP = nil
	for _, c := range []engine.Check{bucketPublic{}, bucketUniformAccess{}, bucketPublicAccessPrevention{}, firewallOpenIngress{}, iamPublicMember{}, iamPrimitiveRole{}} {
		if fs := evalCheck(t, c, st); len(fs) != 0 {
			t.Fatalf("%s on nil gcp state should yield nothing, got %d", c.Spec().ID, len(fs))
		}
	}
}
