// Package reachability approximates AWS Reachability-Analyzer logic locally — no
// API cost, no extra permissions — to tell genuinely internet-reachable
// resources apart from "open on paper but unreachable" ones. A security group
// open to 0.0.0.0/0 on an instance with no public IP, or in a subnet whose route
// table has no internet-gateway route, is not actually exposed; modeling that is
// the false-positive reduction the plan calls for (§9.5).
//
// Verdicts are deliberately three-valued: a finding is downgraded/annotated, not
// dropped, and "unknown" is returned whenever the topology needed to decide is
// absent (e.g. a denied DescribeSubnets) rather than guessing "not reachable".
package reachability

import (
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// Result holds the precomputed topology indexes for reachability queries.
type Result struct {
	subnetRT    map[string]string // subnetID -> explicitly associated routeTableID
	mainRT      map[string]string // vpcID    -> main routeTableID
	rtIGW       map[string]bool   // routeTableID -> has a default route to an IGW
	sgWorldOpen map[string]bool   // sgID -> has a world-open ingress rule
	hasTopology bool              // any subnet/route-table data was collected
}

// Solve indexes the collected topology for reachability queries. It is pure and
// safe on nil/empty state.
func Solve(a *state.AWS) *Result {
	r := &Result{
		subnetRT:    map[string]string{},
		mainRT:      map[string]string{},
		rtIGW:       map[string]bool{},
		sgWorldOpen: map[string]bool{},
	}
	if a == nil {
		return r
	}
	for _, rt := range a.RouteTables {
		r.rtIGW[rt.ID] = rt.IGWRoute
		if rt.Main && rt.VPCID != "" {
			r.mainRT[rt.VPCID] = rt.ID
		}
	}
	for _, sn := range a.Subnets {
		if sn.RouteTableID != "" {
			r.subnetRT[sn.ID] = sn.RouteTableID
		}
	}
	for _, sg := range a.SecurityGroups {
		r.sgWorldOpen[sg.ID] = sg.WorldOpen()
	}
	r.hasTopology = len(a.Subnets) > 0 || len(a.RouteTables) > 0
	return r
}

// Instance reports whether an instance is reachable from the internet: it needs
// a public IP, a subnet whose effective route table reaches an internet gateway,
// and a security group that admits inbound traffic from the world. Missing data
// yields Unknown rather than a false negative.
func (r *Result) Instance(inst state.EC2Instance) findings.Reachability {
	if inst.PublicIP == "" {
		return findings.ReachNo // not addressable from the internet
	}
	if !r.hasTopology {
		return findings.ReachUnknown
	}
	if inst.SubnetID == "" {
		// Subnet unknown: do not fall back to the VPC main table, which may not
		// govern this instance — a wrong table yields a confident-but-wrong verdict.
		return findings.ReachUnknown
	}

	rtID := r.effectiveRouteTable(inst.SubnetID, inst.VPCID)
	if rtID == "" {
		return findings.ReachUnknown // subnet/VPC topology not resolvable
	}
	// A route table id that is not in the index means its routes were not
	// collected (e.g. a denied/partial DescribeRouteTables); the IGW dimension is
	// then unknown, not "no internet route".
	igw, rtKnown := r.rtIGW[rtID]
	if !rtKnown {
		return findings.ReachUnknown
	}

	if len(inst.SecurityGroupIDs) == 0 {
		return findings.ReachUnknown // cannot assess the inbound filter
	}
	worldOpen := false
	for _, id := range inst.SecurityGroupIDs {
		if r.sgWorldOpen[id] {
			worldOpen = true
			break
		}
	}

	if igw && worldOpen {
		return findings.ReachYes
	}
	return findings.ReachNo
}

// effectiveRouteTable resolves the route table governing a subnet: its explicit
// association if any, otherwise the VPC's main table. Empty if neither is known.
func (r *Result) effectiveRouteTable(subnetID, vpcID string) string {
	if rt, ok := r.subnetRT[subnetID]; ok {
		return rt
	}
	return r.mainRT[vpcID]
}

// Annotate sets the Reachable field on exposure findings whose reachability can
// be determined from topology. It is conservative: it only annotates per-instance
// public-IP findings (where instance subnet/SG attachment is fully known) and
// leaves other findings at their default (unknown).
func Annotate(fs []findings.Finding, a *state.AWS, r *Result) {
	if a == nil {
		return
	}
	byID := map[string]state.EC2Instance{}
	for _, inst := range a.Instances {
		byID[inst.ID] = inst
	}
	for i := range fs {
		if fs[i].CheckID != "aws_ec2_instance_public_ip" {
			continue
		}
		if inst, ok := byID[fs[i].Resource.ID]; ok {
			fs[i].Reachable = r.Instance(inst)
		}
	}
}
