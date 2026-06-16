package chain

import (
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// stateWithPrivilegedIdentities builds AWS IAM state where user "deploy" can
// escalate via iam:PutUserPolicy and role "Builder" holds admin via a wildcard
// inline policy.
func stateWithPrivilegedIdentities() *state.AWS {
	privesc := state.PolicyDocument{Statements: []state.PolicyStatement{
		{Effect: "Allow", Actions: []string{"iam:PutUserPolicy"}, Resources: []string{"*"}},
	}}
	adminWildcard := state.PolicyDocument{Statements: []state.PolicyStatement{
		{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}},
	}}
	return &state.AWS{
		Account: "111122223333",
		IAM: state.IAMState{
			Collected: true,
			Users:     []state.IAMUser{{Name: "deploy", Policies: []state.PolicyDocument{privesc}}},
			Roles:     []state.IAMRole{{Name: "Builder", ARN: "arn:aws:iam::111122223333:role/Builder", Policies: []state.PolicyDocument{adminWildcard}}},
		},
	}
}

func live(arn, surface, resource, lastfour string) LiveKey {
	return LiveKey{
		Cred:    secrets.AWSKeyCredential{AccessKeyID: "AKIA000000000000" + lastfour, Surface: surface, Resource: resource, Region: "us-east-1"},
		ARN:     arn,
		Account: "111122223333",
	}
}

func TestSynthesize_PrivescChain(t *testing.T) {
	now := time.Now().UTC()
	keys := []LiveKey{live("arn:aws:iam::111122223333:user/deploy", "lambda_env", "ingest", "0001")}

	fs, paths := Synthesize(stateWithPrivilegedIdentities(), keys, now)
	if len(fs) != 1 || len(paths) != 1 {
		t.Fatalf("expected 1 finding + 1 path, got %d/%d", len(fs), len(paths))
	}
	f := fs[0]
	if f.Severity != findings.SeverityCritical || f.CheckID != CheckID {
		t.Fatalf("unexpected finding: sev=%s check=%s", f.Severity, f.CheckID)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Verdict != "confirmed" {
		t.Fatalf("chain finding must carry confirmed evidence: %+v", f.Evidence)
	}
	if !strings.Contains(f.Description, "iam:putuserpolicy") {
		t.Errorf("description should name the privesc action: %q", f.Description)
	}
	// Hard invariant: no raw secret material, only the masked id.
	if !strings.Contains(f.Evidence[0].Request, "****0001") {
		t.Errorf("evidence should reference the masked key: %q", f.Evidence[0].Request)
	}

	p := paths[0]
	if p.Score != 90 || p.Severity != findings.SeverityCritical {
		t.Fatalf("privesc path score/severity = %d/%s, want 90/critical", p.Score, p.Severity)
	}
	if len(p.Nodes) != 3 || len(p.Edges) != 3 {
		t.Fatalf("path should be 3 nodes / 3 edges, got %d/%d", len(p.Nodes), len(p.Edges))
	}
	// The terminal node id must match the graph builder's principal node id so the
	// chain coincides with the trust dimension's node rather than duplicating it.
	want := graph.PrincipalNodeID("user/deploy")
	if p.Nodes[2].ID != want {
		t.Errorf("terminal node id = %q, want %q", p.Nodes[2].ID, want)
	}
	if p.Edges[0].Kind != graph.EdgeExposedSecret || p.Edges[1].Kind != graph.EdgeLiveCredential || p.Edges[2].Kind != graph.EdgeCanEscalate {
		t.Errorf("unexpected edge kinds: %s/%s/%s", p.Edges[0].Kind, p.Edges[1].Kind, p.Edges[2].Kind)
	}
}

func TestSynthesize_AdminChainScoresHigher(t *testing.T) {
	now := time.Now().UTC()
	keys := []LiveKey{live("arn:aws:sts::111122223333:assumed-role/Builder/session-1", "ec2_userdata", "i-0abc", "0002")}

	fs, paths := Synthesize(stateWithPrivilegedIdentities(), keys, now)
	if len(fs) != 1 || len(paths) != 1 {
		t.Fatalf("expected 1 finding + 1 path, got %d/%d", len(fs), len(paths))
	}
	if paths[0].Score != 95 {
		t.Errorf("admin chain score = %d, want 95", paths[0].Score)
	}
	if paths[0].Edges[2].Kind != graph.EdgeHoldsAdmin {
		t.Errorf("admin chain final hop = %s, want holds-admin", paths[0].Edges[2].Kind)
	}
	// assumed-role ARN must resolve to the Builder role node.
	if paths[0].Nodes[2].ID != graph.PrincipalNodeID("role/Builder") {
		t.Errorf("assumed-role identity = %q, want role/Builder node", paths[0].Nodes[2].ID)
	}
}

func TestSynthesize_NoPrivilegeNoChain(t *testing.T) {
	now := time.Now().UTC()
	// Live key maps to an identity not present in the privilege graph: no chain.
	keys := []LiveKey{live("arn:aws:iam::111122223333:user/readonly", "ssm_parameter", "/app/key", "0003")}
	fs, paths := Synthesize(stateWithPrivilegedIdentities(), keys, now)
	if len(fs) != 0 || len(paths) != 0 {
		t.Fatalf("a live key on an unprivileged identity must not chain, got %d/%d", len(fs), len(paths))
	}
}

func TestSynthesize_MalformedARNSkipped(t *testing.T) {
	now := time.Now().UTC()
	keys := []LiveKey{
		live("not-an-arn", "lambda_env", "fn", "0004"),
		live("arn:aws:iam::111122223333:group/admins", "lambda_env", "fn", "0005"), // unsupported principal kind
	}
	fs, paths := Synthesize(stateWithPrivilegedIdentities(), keys, now)
	if len(fs) != 0 || len(paths) != 0 {
		t.Fatalf("malformed/unsupported ARNs must be skipped, got %d/%d", len(fs), len(paths))
	}
}

func TestSynthesize_EmptyInputs(t *testing.T) {
	now := time.Now().UTC()
	if fs, paths := Synthesize(nil, []LiveKey{live("arn:aws:iam::1:user/x", "lambda_env", "f", "0006")}, now); fs != nil || paths != nil {
		t.Error("nil state should yield nothing")
	}
	if fs, paths := Synthesize(stateWithPrivilegedIdentities(), nil, now); fs != nil || paths != nil {
		t.Error("no live keys should yield nothing")
	}
}

func TestParsePrincipalARN(t *testing.T) {
	tests := []struct {
		arn        string
		kind, name string
	}{
		{"arn:aws:iam::111122223333:user/deploy", "user", "deploy"},
		{"arn:aws:iam::111122223333:user/team/deploy", "user", "deploy"},
		{"arn:aws:iam::111122223333:role/Builder", "role", "Builder"},
		{"arn:aws:sts::111122223333:assumed-role/Builder/session", "role", "Builder"},
		{"arn:aws:iam::111122223333:root", "", ""},
		{"arn:aws:iam::111122223333:group/admins", "", ""},
		{"garbage", "", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		k, n := parsePrincipalARN(tc.arn)
		if k != tc.kind || n != tc.name {
			t.Errorf("parsePrincipalARN(%q) = (%q,%q), want (%q,%q)", tc.arn, k, n, tc.kind, tc.name)
		}
	}
}
