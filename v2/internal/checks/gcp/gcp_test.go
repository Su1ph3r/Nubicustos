package gcp

import (
	"strings"
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

func TestGCPExposedSecret(t *testing.T) {
	st := stateWith(&state.GCP{SecretHits: []state.SecretHit{
		{Detector: "aws_access_key_id", Kind: "AWS key", Surface: "gcp_function_env", Resource: "fn1", Account: "proj-a", Locator: "AWS_KEY", Masked: "****1234"},
		{Detector: "generic_secret", Kind: "secret", Surface: "gcp_instance_metadata", Resource: "vm1", Account: "proj-a", Locator: "startup-script", Masked: "****abcd"},
		{Detector: "generic_secret", Kind: "secret", Surface: "gcp_function_env", Resource: "fn2", Account: "proj-b", Locator: "TOKEN", Masked: "****ef01"},
	}})
	fs := evalCheck(t, exposedSecret{}, st)
	if len(fs) != 2 { // one aggregate finding per project (proj-a, proj-b)
		t.Fatalf("expected one aggregate finding per project, got %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Severity != findings.SeverityHigh {
			t.Errorf("exposed-secret should be high severity, got %s", f.Severity)
		}
	}
	if got := evalCheck(t, exposedSecret{}, stateWith(&state.GCP{})); len(got) != 0 {
		t.Fatalf("no secret hits should yield no findings, got %d", len(got))
	}
}

func TestCloudSQLChecks(t *testing.T) {
	st := stateWith(&state.GCP{CloudSQL: []state.CloudSQLInstance{
		{Name: "db1", Project: "p1", PublicIP: true, RequireSSL: false, BackupEnabled: false,
			AuthorizedNetworks: []string{"0.0.0.0/0"}},
	}})
	if fs := evalCheck(t, cloudSQLPublicIP{}, st); len(fs) != 1 {
		t.Fatalf("expected public-ip finding, got %d", len(fs))
	}
	if fs := evalCheck(t, cloudSQLNoSSL{}, st); len(fs) != 1 {
		t.Fatalf("expected no-ssl finding, got %d", len(fs))
	}
	if fs := evalCheck(t, cloudSQLAuthorizedAll{}, st); len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected one high authorized-all finding, got %+v", fs)
	}
	if fs := evalCheck(t, cloudSQLNoBackup{}, st); len(fs) != 1 {
		t.Fatalf("expected backup-disabled finding, got %d", len(fs))
	}
	// A hardened instance produces none.
	hardened := stateWith(&state.GCP{CloudSQL: []state.CloudSQLInstance{
		{Name: "db2", PublicIP: false, RequireSSL: true, BackupEnabled: true, AuthorizedNetworks: []string{"203.0.113.0/24"}},
	}})
	for _, c := range []engine.Check{cloudSQLPublicIP{}, cloudSQLNoSSL{}, cloudSQLAuthorizedAll{}, cloudSQLNoBackup{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened instance should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestComputeChecks(t *testing.T) {
	st := stateWith(&state.GCP{ComputeVMs: []state.ComputeInstance{
		{Name: "vm1", Project: "p1", Zone: "us-central1-a", HasPublicIP: true, ShieldedVM: false,
			DefaultSAFullAPI: true, SerialPortEnabled: true},
	}})
	if fs := evalCheck(t, computeDefaultSAFullAPI{}, st); len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected one high default-SA finding, got %+v", fs)
	}
	if fs := evalCheck(t, computeShieldedDisabled{}, st); len(fs) != 1 {
		t.Fatalf("expected shielded-disabled finding, got %d", len(fs))
	}
	if fs := evalCheck(t, computeSerialPort{}, st); len(fs) != 1 {
		t.Fatalf("expected serial-port finding, got %d", len(fs))
	}
	// A hardened VM produces none.
	hardened := stateWith(&state.GCP{ComputeVMs: []state.ComputeInstance{
		{Name: "vm2", ShieldedVM: true, DefaultSAFullAPI: false, SerialPortEnabled: false},
	}})
	for _, c := range []engine.Check{computeDefaultSAFullAPI{}, computeShieldedDisabled{}, computeSerialPort{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened VM should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestKMSChecks(t *testing.T) {
	st := stateWith(&state.GCP{KMSKeys: []state.KMSCryptoKey{
		{Name: "k1", Project: "p1", KeyRing: "r1", Purpose: "ENCRYPT_DECRYPT", RotationEnabled: false, PublicIAM: true},
		{Name: "asym", Project: "p1", KeyRing: "r1", Purpose: "ASYMMETRIC_SIGN", RotationEnabled: false}, // not rotatable → not flagged
	}})
	if fs := evalCheck(t, kmsRotationDisabled{}, st); len(fs) != 1 || fs[0].Resource.Name != "k1" {
		t.Fatalf("only the symmetric key without rotation should be flagged, got %+v", fs)
	}
	if fs := evalCheck(t, kmsPublicIAM{}, st); len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected one high public-IAM finding, got %+v", fs)
	}
	hardened := stateWith(&state.GCP{KMSKeys: []state.KMSCryptoKey{
		{Name: "k2", Purpose: "ENCRYPT_DECRYPT", RotationEnabled: true, PublicIAM: false},
	}})
	for _, c := range []engine.Check{kmsRotationDisabled{}, kmsPublicIAM{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened key should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestGKEChecks(t *testing.T) {
	st := stateWith(&state.GCP{GKEClusters: []state.GKECluster{
		{Name: "c1", Project: "p1", LegacyABAC: true, NetworkPolicyEnabled: false, MasterAuthorizedNetworks: false},
	}})
	if fs := evalCheck(t, gkeLegacyABAC{}, st); len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected one high legacy-ABAC finding, got %+v", fs)
	}
	if fs := evalCheck(t, gkeNetworkPolicyDisabled{}, st); len(fs) != 1 {
		t.Fatalf("expected network-policy finding, got %d", len(fs))
	}
	if fs := evalCheck(t, gkeMasterNetworksOpen{}, st); len(fs) != 1 {
		t.Fatalf("expected master-authorized-networks finding, got %d", len(fs))
	}
	hardened := stateWith(&state.GCP{GKEClusters: []state.GKECluster{
		{Name: "c2", LegacyABAC: false, NetworkPolicyEnabled: true, MasterAuthorizedNetworks: true},
	}})
	for _, c := range []engine.Check{gkeLegacyABAC{}, gkeNetworkPolicyDisabled{}, gkeMasterNetworksOpen{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened cluster should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestAuditLoggingCheck(t *testing.T) {
	st := stateWith(&state.GCP{AuditConfig: []state.GCPAuditLogging{
		{Project: "p1", Collected: true, DataReadAll: false, DataWriteAll: false}, // flagged
		{Project: "p2", Collected: true, DataReadAll: true, DataWriteAll: true},   // fully logged
		{Project: "p3", Collected: false},                                         // denied → not judged
	}})
	fs := evalCheck(t, auditLoggingNotConfigured{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "p1" {
		t.Fatalf("only the under-logged, collected project should be flagged, got %+v", fs)
	}
}

func TestCrossProjectSA(t *testing.T) {
	st := stateWith(&state.GCP{IAMBindings: []state.GCPIAMBinding{
		{Project: "proj-a", Role: "roles/editor", Members: []string{
			"serviceAccount:ci@proj-b.iam.gserviceaccount.com",               // cross-project → flag
			"serviceAccount:local@proj-a.iam.gserviceaccount.com",            // same project → ok
			"serviceAccount:service-1@gcp-sa-pubsub.iam.gserviceaccount.com", // Google-managed → ok
			"user:alice@example.com",                                         // not an SA → ok
		}},
	}})
	fs := evalCheck(t, crossProjectSA{}, st)
	if len(fs) != 1 || !strings.Contains(fs[0].Description, "proj-b") {
		t.Fatalf("only the cross-project user-managed SA should be flagged, got %+v", fs)
	}
}

func TestGCPCrossCloudFederation(t *testing.T) {
	st := stateWith(&state.GCP{WIFProviders: []state.GCPWorkloadIdentityProvider{
		{Project: "p1", Pool: "pool-aws", Provider: "aws-prov", Kind: "aws", AWSAccount: "111122223333"},
		{Project: "p1", Pool: "pool-az", Provider: "az-prov", Kind: "oidc", Issuer: "https://sts.windows.net/tenant-guid/"},
		{Project: "p1", Pool: "pool-gh", Provider: "gh-prov", Kind: "oidc", Issuer: "https://token.actions.githubusercontent.com"}, // CI, not a cloud
		{Project: "p1", Pool: "pool-dis", Provider: "aws-off", Kind: "aws", AWSAccount: "999", Disabled: true},                     // disabled
	}})
	fs := evalCheck(t, crossCloudFederation{}, st)
	if len(fs) != 2 {
		t.Fatalf("expected 2 cross-cloud findings (AWS, Azure), got %d: %+v", len(fs), fs)
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Resource.Name] = true
	}
	if !got["aws-prov"] || !got["az-prov"] || got["gh-prov"] || got["aws-off"] {
		t.Fatalf("expected aws-prov + az-prov flagged, not gh-prov/aws-off: %v", got)
	}
}

func TestGCPMonitoringAlertMissing(t *testing.T) {
	st := stateWith(&state.GCP{Monitoring: []state.GCPMonitoring{
		{Project: "p1", ReadOK: true,
			Metrics: []state.GCPLogMetric{
				// firewall (2.7) covered: metric matches + alerted.
				{Name: "projects/p1/metrics/fw-changes", Filter: `resource.type="gce_firewall_rule"`},
				// audit config (2.5) has a metric but NO alert.
				{Name: "projects/p1/metrics/audit", Filter: `protoPayload.methodName="SetIamPolicy" AND auditConfigDeltas:*`},
			},
			AlertedMetricNames: []string{"fw-changes"},
		},
	}})
	fs := evalCheck(t, monitoringAlertMissing{}, st)
	flagged := map[string]bool{}
	for _, f := range fs {
		flagged[f.Resource.Name] = true
	}
	if flagged["CIS 2.7"] {
		t.Error("firewall (2.7) is metric+alert covered and must not be flagged")
	}
	if !flagged["CIS 2.5"] {
		t.Error("audit-config (2.5) has a metric but no alert and must be flagged")
	}
	// 8 controls, 1 covered → 7 missing.
	if len(fs) != 7 {
		t.Fatalf("expected 7 missing-monitoring findings, got %d", len(fs))
	}
	// Unread project is not judged.
	notRead := stateWith(&state.GCP{Monitoring: []state.GCPMonitoring{{Project: "p2", ReadOK: false}}})
	if got := evalCheck(t, monitoringAlertMissing{}, notRead); len(got) != 0 {
		t.Fatalf("unread project must not be judged, got %d", len(got))
	}
}

func TestNilGCPStateNoPanic(t *testing.T) {
	st := state.New()
	st.GCP = nil
	for _, c := range []engine.Check{
		bucketPublic{}, bucketUniformAccess{}, bucketPublicAccessPrevention{}, firewallOpenIngress{},
		iamPublicMember{}, iamPrimitiveRole{}, exposedSecret{},
		cloudSQLPublicIP{}, cloudSQLNoSSL{}, cloudSQLAuthorizedAll{}, cloudSQLNoBackup{},
		computeDefaultSAFullAPI{}, computeShieldedDisabled{}, computeSerialPort{},
		kmsRotationDisabled{}, kmsPublicIAM{}, gkeLegacyABAC{}, gkeNetworkPolicyDisabled{}, gkeMasterNetworksOpen{},
		auditLoggingNotConfigured{}, crossProjectSA{}, monitoringAlertMissing{},
	} {
		if fs := evalCheck(t, c, st); len(fs) != 0 {
			t.Fatalf("%s on nil gcp state should yield nothing, got %d", c.Spec().ID, len(fs))
		}
	}
}
