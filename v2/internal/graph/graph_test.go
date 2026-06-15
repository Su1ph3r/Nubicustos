package graph

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/reachability"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// hasEdge reports whether the graph contains an edge of the given kind.
func hasEdge(g *Graph, kind EdgeKind) bool {
	for _, e := range g.Edges {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestAssumeRoleEdgeFromIntraAccountTrust(t *testing.T) {
	st := state.New()
	st.AWS.Account = "111122223333"
	st.SetIAM(state.IAMState{Roles: []state.IAMRole{{
		Name: "app", ARN: "arn:aws:iam::111122223333:role/app",
		TrustPolicy: state.PolicyDocument{Statements: []state.PolicyStatement{
			{Effect: "Allow", AWSPrincipals: []string{"arn:aws:iam::111122223333:user/ci"}},
		}},
	}}})
	g := Build(st, nil)
	if !hasEdge(g, EdgeCanAssume) {
		t.Fatal("expected a can-assume-role edge from the intra-account trust")
	}
}

func TestWildcardTrustProducesCriticalPath(t *testing.T) {
	st := state.New()
	st.AWS.Account = "111122223333"
	st.SetIAM(state.IAMState{Roles: []state.IAMRole{{
		Name: "open", ARN: "arn:aws:iam::111122223333:role/open",
		TrustPolicy: state.PolicyDocument{Statements: []state.PolicyStatement{
			{Effect: "Allow", AWSPrincipals: []string{"*"}},
		}},
	}}})
	g := Build(st, nil)
	p := findPath(t, g, "trust-wildcard:open")
	if p.Severity != findings.SeverityCritical {
		t.Fatalf("wildcard trust path should be critical, got %s", p.Severity)
	}
}

func TestTwoExternalTrustsProduceDistinctPaths(t *testing.T) {
	// A role trusting two external accounts must yield two distinct path IDs, so
	// neither overwrites the other when persisted (attack_paths PK is scan_id,id).
	st := state.New()
	st.AWS.Account = "111122223333"
	st.SetIAM(state.IAMState{Roles: []state.IAMRole{{
		Name: "multi", ARN: "arn:aws:iam::111122223333:role/multi",
		TrustPolicy: state.PolicyDocument{Statements: []state.PolicyStatement{
			{Effect: "Allow", AWSPrincipals: []string{
				"arn:aws:iam::999988887777:root",
				"arn:aws:iam::888877776666:root",
			}},
		}},
	}}})
	g := Build(st, nil)
	ids := map[string]int{}
	for _, p := range g.Paths {
		ids[p.ID]++
	}
	count := 0
	for id, n := range ids {
		if n > 1 {
			t.Fatalf("duplicate path id %q (%d) would overwrite on persist", id, n)
		}
		if len(id) >= len("trust-external:") && id[:len("trust-external:")] == "trust-external:" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 distinct external-trust paths, got %d", count)
	}
}

func TestPrivescEdgeAndPath(t *testing.T) {
	st := state.New()
	st.AWS.Account = "111122223333"
	st.SetIAM(state.IAMState{Users: []state.IAMUser{{
		Name: "deployer",
		Policies: []state.PolicyDocument{{Statements: []state.PolicyStatement{
			{Effect: "Allow", Actions: []string{"iam:CreateAccessKey"}, Resources: []string{"*"}},
		}}},
	}}})
	g := Build(st, nil)
	if !hasEdge(g, EdgeCanEscalate) {
		t.Fatal("expected a can-escalate edge")
	}
	findPath(t, g, "privesc-user:deployer")
}

func TestReachabilityDowngradesUnreachableInstance(t *testing.T) {
	// An IMDSv1 public instance that is NOT reachable (no IGW route) must be
	// downgraded relative to the same instance with no reachability data.
	st := state.New()
	st.AddInstance(state.EC2Instance{ID: "i-1", PublicIP: "203.0.113.1", IMDSv2Required: false,
		VPCID: "vpc-1", SubnetID: "sn-priv", SecurityGroupIDs: []string{"sg-open"}})
	st.AddSecurityGroup(state.SecurityGroup{ID: "sg-open", Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true}}})
	st.AddRouteTable(state.RouteTable{ID: "rt-priv", VPCID: "vpc-1", Main: true, IGWRoute: false})
	st.AddSubnet(state.Subnet{ID: "sn-priv", VPCID: "vpc-1"})

	base := findPath(t, Build(st, nil), "internet-imds-creds:i-1")
	rch := reachability.Solve(st.AWS)
	downgraded := findPath(t, Build(st, rch), "internet-imds-creds:i-1")

	if downgraded.Reachable != findings.ReachNo {
		t.Fatalf("expected not-reachable, got %s", downgraded.Reachable)
	}
	if downgraded.Score >= base.Score {
		t.Fatalf("unreachable path should score lower: base %d, downgraded %d", base.Score, downgraded.Score)
	}
}

func TestReachabilityConfirmsReachableInstance(t *testing.T) {
	st := state.New()
	st.AddInstance(state.EC2Instance{ID: "i-2", PublicIP: "203.0.113.2", IMDSv2Required: true,
		VPCID: "vpc-1", SubnetID: "sn-pub", SecurityGroupIDs: []string{"sg-open"}})
	st.AddSecurityGroup(state.SecurityGroup{ID: "sg-open", Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true}}})
	st.AddRouteTable(state.RouteTable{ID: "rt-pub", VPCID: "vpc-1", IGWRoute: true})
	st.AddSubnet(state.Subnet{ID: "sn-pub", VPCID: "vpc-1", RouteTableID: "rt-pub"})

	rch := reachability.Solve(st.AWS)
	p := findPath(t, Build(st, rch), "internet-exposed-instance:i-2")
	if p.Reachable != findings.ReachYes {
		t.Fatalf("expected confirmed reachable, got %s", p.Reachable)
	}
}

func TestImdsPathNamesResolvedRole(t *testing.T) {
	st := state.New()
	st.AddInstance(state.EC2Instance{ID: "i-3", PublicIP: "203.0.113.3", IMDSv2Required: false, RoleName: "app-role"})
	g := Build(st, nil)
	p := findPath(t, g, "internet-imds-creds:i-3")
	named := false
	for _, n := range p.Nodes {
		if n.Label == "role app-role credentials" {
			named = true
		}
	}
	if !named {
		t.Fatalf("expected the credential node to name role app-role, got %+v", p.Nodes)
	}
}

func TestBuildEmptyStateHasOnlyInternet(t *testing.T) {
	g := Build(state.New(), nil)
	if len(g.Nodes) != 1 || g.Nodes[0].Kind != NodeInternet {
		t.Fatalf("expected only the internet node, got %+v", g.Nodes)
	}
	if len(g.Paths) != 0 {
		t.Fatalf("expected no paths on empty state, got %d", len(g.Paths))
	}
}

func TestBuildNilStateSafe(t *testing.T) {
	g := Build(nil, nil)
	if len(g.Nodes) != 1 || g.Nodes[0].ID != InternetNodeID {
		t.Fatalf("nil state should still yield the internet node, got %+v", g.Nodes)
	}
}

// findPath returns the path with the given id, or fails.
func findPath(t *testing.T, g *Graph, id string) Path {
	t.Helper()
	for _, p := range g.Paths {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("path %q not found in %+v", id, pathIDs(g))
	return Path{}
}

func pathIDs(g *Graph) []string {
	var ids []string
	for _, p := range g.Paths {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestPublicRDSPath(t *testing.T) {
	st := state.New()
	st.AddRDSInstance(state.RDSInstance{ID: "db-1", Region: "us-east-1", Engine: "postgres", Public: true})
	g := Build(st, nil)

	p := findPath(t, g, "internet-rds:db-1")
	if p.Severity != findings.SeverityHigh {
		t.Fatalf("expected high severity, got %s (score %d)", p.Severity, p.Score)
	}
	if len(p.Edges) != 1 || p.Edges[0].Kind != EdgeExposedToInternet || p.Edges[0].Src != InternetNodeID {
		t.Fatalf("expected one internet-exposure edge, got %+v", p.Edges)
	}
}

func TestNonPublicRDSNoPath(t *testing.T) {
	st := state.New()
	st.AddRDSInstance(state.RDSInstance{ID: "db-private", Public: false})
	g := Build(st, nil)
	for _, p := range g.Paths {
		t.Fatalf("private RDS must not produce a path, got %q", p.ID)
	}
}

func TestPublicInstanceWithIMDSv1IsTwoHopCredentialPath(t *testing.T) {
	st := state.New()
	st.AddInstance(state.EC2Instance{ID: "i-1", Region: "us-east-1", PublicIP: "203.0.113.10", IMDSv2Required: false})
	g := Build(st, nil)

	p := findPath(t, g, "internet-imds-creds:i-1")
	if len(p.Edges) != 2 {
		t.Fatalf("expected 2 hops (expose + metadata-creds), got %d", len(p.Edges))
	}
	if p.Edges[1].Kind != EdgeMetadataCreds {
		t.Fatalf("second hop should be the metadata-credential edge, got %s", p.Edges[1].Kind)
	}
	// 0.7 x 0.85 = 59.5 -> 60 -> high
	if p.Severity != findings.SeverityHigh {
		t.Fatalf("expected high severity, got %s (score %d)", p.Severity, p.Score)
	}
}

func TestPublicInstanceWithIMDSv2IsSingleHop(t *testing.T) {
	st := state.New()
	st.AddInstance(state.EC2Instance{ID: "i-2", PublicIP: "203.0.113.20", IMDSv2Required: true})
	g := Build(st, nil)

	p := findPath(t, g, "internet-exposed-instance:i-2")
	if len(p.Edges) != 1 {
		t.Fatalf("IMDSv2-enforced instance should be a single-hop exposure, got %d edges", len(p.Edges))
	}
	// No metadata-credential edge anywhere.
	for _, e := range g.Edges {
		if e.Kind == EdgeMetadataCreds {
			t.Fatal("IMDSv2-enforced instance must not produce a metadata-credential edge")
		}
	}
}

func TestPrivateInstanceNoExposure(t *testing.T) {
	st := state.New()
	st.AddInstance(state.EC2Instance{ID: "i-private", PublicIP: ""})
	g := Build(st, nil)
	if len(g.Paths) != 0 {
		t.Fatalf("instance without a public IP must not be exposed, got %+v", pathIDs(g))
	}
}

func TestRootAccessKeysNoMFAIsCritical(t *testing.T) {
	st := state.New()
	st.SetIAM(state.IAMState{RootAccessKeys: true, RootMFAEnabled: false})
	g := Build(st, nil)

	p := findPath(t, g, "admin-root")
	// Score is 0.5 x 1.0 = 50 (medium band), but the no-MFA floor forces critical.
	if p.Severity != findings.SeverityCritical {
		t.Fatalf("root keys without MFA must be critical, got %s (score %d)", p.Severity, p.Score)
	}
}

func TestRootAccessKeysWithMFANoFloor(t *testing.T) {
	st := state.New()
	st.SetIAM(state.IAMState{RootAccessKeys: true, RootMFAEnabled: true})
	g := Build(st, nil)
	p := findPath(t, g, "admin-root")
	// 50 -> medium band, no critical floor applied.
	if p.Severity != findings.SeverityMedium {
		t.Fatalf("expected medium (no floor) for MFA-protected root keys, got %s", p.Severity)
	}
}

func TestAdminUserPath(t *testing.T) {
	st := state.New()
	st.SetIAM(state.IAMState{Users: []state.IAMUser{
		{Name: "alice", AdminAttached: true, ConsoleAccess: true, MFAEnabled: false},
		{Name: "bob", AdminAttached: false},
	}})
	g := Build(st, nil)

	p := findPath(t, g, "admin-user:alice")
	if p.Edges[0].Kind != EdgeHoldsAdmin {
		t.Fatalf("expected holds-admin edge, got %s", p.Edges[0].Kind)
	}
	// console + no MFA bumps exploitability to 0.7 -> 0.7 x 0.9 = 63 -> high
	if p.Severity != findings.SeverityHigh {
		t.Fatalf("expected high for password-only admin, got %s (score %d)", p.Severity, p.Score)
	}
	for _, q := range g.Paths {
		if q.ID == "admin-user:bob" {
			t.Fatal("non-admin user must not produce an admin path")
		}
	}
	if n := len(g.Principals()); n != 1 {
		t.Fatalf("expected 1 principal node (alice), got %d", n)
	}
}

func TestWorldOpenSecurityGroupExposed(t *testing.T) {
	st := state.New()
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-1", Name: "web", Region: "us-east-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true}},
	})
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-internal", Name: "internal",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: false}},
	})
	g := Build(st, nil)

	findPath(t, g, "internet-sg:sg-1")
	for _, p := range g.Paths {
		if p.ID == "internet-sg:sg-internal" {
			t.Fatal("a non-world-open SG must not be exposed")
		}
	}
}

func TestWorldOpenRangesAllPorts(t *testing.T) {
	ranges, all := worldOpenRanges(state.SecurityGroup{
		Ingress: []state.IngressRule{{Protocol: "-1", FromPort: 0, ToPort: 0, OpenV4: true}},
	})
	if !all || len(ranges) != 1 || ranges[0] != "all ports" {
		t.Fatalf("expected all-ports, got %v all=%v", ranges, all)
	}
}

func TestSeverityForScoreBands(t *testing.T) {
	cases := map[int]findings.Severity{
		95: findings.SeverityCritical,
		80: findings.SeverityCritical,
		79: findings.SeverityHigh,
		60: findings.SeverityHigh,
		40: findings.SeverityMedium,
		20: findings.SeverityLow,
		19: findings.SeverityInfo,
		0:  findings.SeverityInfo,
	}
	for score, want := range cases {
		if got := severityForScore(score); got != want {
			t.Errorf("severityForScore(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestPathsSortedByScoreDescending(t *testing.T) {
	st := state.New()
	st.AddRDSInstance(state.RDSInstance{ID: "db", Public: true}) // ~64 high
	st.AddSecurityGroup(state.SecurityGroup{ID: "sg", Name: "x", // ~24 low
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 80, ToPort: 80, OpenV4: true}}})
	g := Build(st, nil)
	if len(g.Paths) < 2 {
		t.Fatalf("expected at least 2 paths, got %d", len(g.Paths))
	}
	for i := 1; i < len(g.Paths); i++ {
		if g.Paths[i-1].Score < g.Paths[i].Score {
			t.Fatalf("paths not sorted by score desc: %d before %d", g.Paths[i-1].Score, g.Paths[i].Score)
		}
	}
}
