package reachability

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// publicTopology returns AWS state where subnet sn-pub routes to an IGW and sg-open
// is world-open; sn-priv has no IGW route.
func publicTopology() *state.AWS {
	return &state.AWS{
		SecurityGroups: []state.SecurityGroup{
			{ID: "sg-open", Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true}}},
			{ID: "sg-closed", Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: false}}},
		},
		RouteTables: []state.RouteTable{
			{ID: "rt-pub", VPCID: "vpc-1", IGWRoute: true},
			{ID: "rt-priv", VPCID: "vpc-1", Main: true, IGWRoute: false},
		},
		Subnets: []state.Subnet{
			{ID: "sn-pub", VPCID: "vpc-1", RouteTableID: "rt-pub"},
			{ID: "sn-priv", VPCID: "vpc-1"}, // no explicit RT -> falls back to main (rt-priv)
		},
	}
}

func TestReachableInstance(t *testing.T) {
	r := Solve(publicTopology())
	inst := state.EC2Instance{ID: "i-1", PublicIP: "203.0.113.1", VPCID: "vpc-1", SubnetID: "sn-pub", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachYes {
		t.Fatalf("public IP + IGW route + open SG should be reachable, got %s", got)
	}
}

func TestNotReachableNoIGWRoute(t *testing.T) {
	r := Solve(publicTopology())
	// sn-priv falls back to the main route table (rt-priv), which has no IGW route.
	inst := state.EC2Instance{ID: "i-2", PublicIP: "203.0.113.2", VPCID: "vpc-1", SubnetID: "sn-priv", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachNo {
		t.Fatalf("no IGW route should be not-reachable, got %s", got)
	}
}

func TestNotReachableNoOpenSG(t *testing.T) {
	r := Solve(publicTopology())
	inst := state.EC2Instance{ID: "i-3", PublicIP: "203.0.113.3", VPCID: "vpc-1", SubnetID: "sn-pub", SecurityGroupIDs: []string{"sg-closed"}}
	if got := r.Instance(inst); got != findings.ReachNo {
		t.Fatalf("no world-open SG should be not-reachable, got %s", got)
	}
}

func TestNotReachableNoPublicIP(t *testing.T) {
	r := Solve(publicTopology())
	inst := state.EC2Instance{ID: "i-4", PublicIP: "", VPCID: "vpc-1", SubnetID: "sn-pub", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachNo {
		t.Fatalf("no public IP should be not-reachable, got %s", got)
	}
}

func TestUnknownWhenNoTopology(t *testing.T) {
	r := Solve(&state.AWS{}) // no subnets/route tables collected
	inst := state.EC2Instance{ID: "i-5", PublicIP: "203.0.113.5", SubnetID: "sn-x", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachUnknown {
		t.Fatalf("absent topology should yield unknown, got %s", got)
	}
}

func TestUnknownWhenNoSGData(t *testing.T) {
	r := Solve(publicTopology())
	inst := state.EC2Instance{ID: "i-6", PublicIP: "203.0.113.6", VPCID: "vpc-1", SubnetID: "sn-pub"} // no SG ids
	if got := r.Instance(inst); got != findings.ReachUnknown {
		t.Fatalf("missing SG attachment should yield unknown, got %s", got)
	}
}

func TestUnknownWhenSubnetUnresolvable(t *testing.T) {
	r := Solve(publicTopology())
	// Subnet not in any table and VPC has no... actually vpc-1 has a main table;
	// use an unknown VPC so neither explicit nor main resolves.
	inst := state.EC2Instance{ID: "i-7", PublicIP: "203.0.113.7", VPCID: "vpc-unknown", SubnetID: "sn-unknown", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachUnknown {
		t.Fatalf("unresolvable subnet/VPC should yield unknown, got %s", got)
	}
}

func TestUnknownWhenSubnetIDEmpty(t *testing.T) {
	// A public instance with no known subnet must not be judged via the VPC main
	// table — that table may not govern it. Verdict must be unknown, not a
	// confident (and possibly wrong) reachable/not-reachable.
	r := Solve(publicTopology())
	inst := state.EC2Instance{ID: "i-nosubnet", PublicIP: "203.0.113.9", VPCID: "vpc-1", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachUnknown {
		t.Fatalf("empty subnet id should yield unknown, got %s", got)
	}
}

func TestUnknownWhenRouteTableNotCollected(t *testing.T) {
	// Subnet explicitly references a route table whose routes were not collected
	// (partial DescribeRouteTables). The IGW dimension is unknown, not "no route".
	a := &state.AWS{
		SecurityGroups: []state.SecurityGroup{{ID: "sg-open", Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true}}}},
		Subnets:        []state.Subnet{{ID: "sn-x", VPCID: "vpc-1", RouteTableID: "rt-missing"}},
		// no RouteTables collected for rt-missing
	}
	r := Solve(a)
	inst := state.EC2Instance{ID: "i-x", PublicIP: "203.0.113.8", VPCID: "vpc-1", SubnetID: "sn-x", SecurityGroupIDs: []string{"sg-open"}}
	if got := r.Instance(inst); got != findings.ReachUnknown {
		t.Fatalf("uncollected route table should yield unknown (not not-reachable), got %s", got)
	}
}

func TestAnnotateSetsReachableOnPublicIPFinding(t *testing.T) {
	a := publicTopology()
	a.Instances = []state.EC2Instance{
		{ID: "i-pub", PublicIP: "203.0.113.1", VPCID: "vpc-1", SubnetID: "sn-pub", SecurityGroupIDs: []string{"sg-open"}},
	}
	r := Solve(a)
	fs := []findings.Finding{
		{ID: "x", CheckID: "aws_ec2_instance_public_ip", Resource: findings.Resource{ID: "i-pub"}, Reachable: findings.ReachUnknown},
		{ID: "y", CheckID: "aws_s3_public_access", Resource: findings.Resource{ID: "b"}, Reachable: findings.ReachUnknown},
	}
	Annotate(fs, a, r)
	if fs[0].Reachable != findings.ReachYes {
		t.Fatalf("public-IP finding should be annotated reachable, got %s", fs[0].Reachable)
	}
	if fs[1].Reachable != findings.ReachUnknown {
		t.Fatalf("non-exposure finding should be untouched, got %s", fs[1].Reachable)
	}
}

func TestPeeringExposures(t *testing.T) {
	a := &state.AWS{
		RouteTables: []state.RouteTable{
			// vpc-pub reaches the internet and routes to the peering.
			{ID: "rt-pub", VPCID: "vpc-pub", IGWRoute: true, PeeringIDs: []string{"pcx-1"}},
			// vpc-priv has no IGW, but routes back over the peering.
			{ID: "rt-priv", VPCID: "vpc-priv", PeeringIDs: []string{"pcx-1"}},
		},
		Peerings: []state.VPCPeering{
			{ID: "pcx-1", Region: "us-east-1", VPCA: "vpc-pub", VPCB: "vpc-priv", Active: true},
		},
	}
	ex := PeeringExposures(a)
	if len(ex) != 1 {
		t.Fatalf("expected 1 peering exposure, got %d: %+v", len(ex), ex)
	}
	if ex[0].PrivateVPC != "vpc-priv" || ex[0].InternetVPC != "vpc-pub" || ex[0].PeeringID != "pcx-1" {
		t.Fatalf("unexpected exposure: %+v", ex[0])
	}
}

func TestPeeringExposuresInactiveSkipped(t *testing.T) {
	a := &state.AWS{
		RouteTables: []state.RouteTable{
			{ID: "rt-pub", VPCID: "vpc-pub", IGWRoute: true, PeeringIDs: []string{"pcx-1"}},
			{ID: "rt-priv", VPCID: "vpc-priv", PeeringIDs: []string{"pcx-1"}},
		},
		Peerings: []state.VPCPeering{
			{ID: "pcx-1", VPCA: "vpc-pub", VPCB: "vpc-priv", Active: false}, // pending/deleted
		},
	}
	if ex := PeeringExposures(a); len(ex) != 0 {
		t.Fatalf("inactive peering must not expose, got %+v", ex)
	}
}

func TestPeeringExposuresRequiresBothRoutes(t *testing.T) {
	// Only the internet side routes to the peering; no return route on the private
	// side, so no bidirectional path -> not flagged.
	a := &state.AWS{
		RouteTables: []state.RouteTable{
			{ID: "rt-pub", VPCID: "vpc-pub", IGWRoute: true, PeeringIDs: []string{"pcx-1"}},
			{ID: "rt-priv", VPCID: "vpc-priv"}, // no peering route
		},
		Peerings: []state.VPCPeering{
			{ID: "pcx-1", VPCA: "vpc-pub", VPCB: "vpc-priv", Active: true},
		},
	}
	if ex := PeeringExposures(a); len(ex) != 0 {
		t.Fatalf("one-way route must not expose, got %+v", ex)
	}
}

func TestPeeringExposuresBothInternetNotFlagged(t *testing.T) {
	// Both VPCs have their own IGW: neither is the "private" side.
	a := &state.AWS{
		RouteTables: []state.RouteTable{
			{ID: "rt-a", VPCID: "vpc-a", IGWRoute: true, PeeringIDs: []string{"pcx-1"}},
			{ID: "rt-b", VPCID: "vpc-b", IGWRoute: true, PeeringIDs: []string{"pcx-1"}},
		},
		Peerings: []state.VPCPeering{{ID: "pcx-1", VPCA: "vpc-a", VPCB: "vpc-b", Active: true}},
	}
	if ex := PeeringExposures(a); len(ex) != 0 {
		t.Fatalf("two internet VPCs should not produce a private-exposure finding, got %+v", ex)
	}
}

func TestPeeringExposuresNilSafe(t *testing.T) {
	if ex := PeeringExposures(nil); ex != nil {
		t.Fatalf("nil state should yield nil, got %+v", ex)
	}
}
