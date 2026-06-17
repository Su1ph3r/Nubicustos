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
	"fmt"
	"net"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// Result holds the precomputed topology indexes for reachability queries.
type Result struct {
	subnetRT      map[string]string // subnetID -> explicitly associated routeTableID
	mainRT        map[string]string // vpcID    -> main routeTableID
	rtIGW         map[string]bool   // routeTableID -> has a default route to an IGW
	sgWorldOpen   map[string]bool   // sgID -> has a world-open ingress rule
	subnetHasNACL map[string]bool   // subnetID -> a network ACL was collected for it
	subnetNACLNet map[string]bool   // subnetID -> its ACL admits the internet inbound (allow to 0.0.0.0/0 or ::/0)
	hasTopology   bool              // any subnet/route-table data was collected
}

// Solve indexes the collected topology for reachability queries. It is pure and
// safe on nil/empty state.
func Solve(a *state.AWS) *Result {
	r := &Result{
		subnetRT:      map[string]string{},
		mainRT:        map[string]string{},
		rtIGW:         map[string]bool{},
		sgWorldOpen:   map[string]bool{},
		subnetHasNACL: map[string]bool{},
		subnetNACLNet: map[string]bool{},
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
	// A network ACL admits the internet if it has any inbound ALLOW rule open to
	// 0.0.0.0/0 or ::/0. A subnet whose ACL has none blocks the internet outright,
	// regardless of port. (A port-specific public allow is treated conservatively
	// as admitting the internet, so we never downgrade a finding we cannot rule
	// out, only those a clearly-restrictive ACL blocks.)
	for _, acl := range a.NetworkACLs {
		admits := false
		for _, rule := range acl.Inbound {
			if rule.Allow && (rule.CIDR == "0.0.0.0/0" || rule.CIDR == "::/0") {
				admits = true
				break
			}
		}
		for _, sn := range acl.SubnetIDs {
			r.subnetHasNACL[sn] = true
			if admits {
				r.subnetNACLNet[sn] = true
			}
		}
	}
	r.hasTopology = len(a.Subnets) > 0 || len(a.RouteTables) > 0
	return r
}

// naclBlocksInternet reports whether a subnet's network ACL is known and admits
// no internet inbound (so it blocks traffic an open security group would
// otherwise allow). False when no ACL was collected for the subnet, so missing
// data never produces a false "not reachable".
func (r *Result) naclBlocksInternet(subnetID string) bool {
	return r.subnetHasNACL[subnetID] && !r.subnetNACLNet[subnetID]
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
		// A subnet ACL that admits no internet inbound blocks the path even though
		// the security group is world-open: the instance is not actually reachable.
		if r.naclBlocksInternet(inst.SubnetID) {
			return findings.ReachNo
		}
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

// PeeringExposure is a private VPC reachable from an internet-exposed VPC across
// an active peering connection. The exposure is topological: each VPC's own
// config looks fine (the private one has no internet gateway), but a foothold in
// the internet-exposed VPC can pivot across the peering into the private one. A
// per-resource or per-VPC config scan misses it because the path spans two VPCs.
type PeeringExposure struct {
	PrivateVPC  string // the VPC with no internet gateway of its own
	InternetVPC string // the peered VPC that does reach the internet
	PeeringID   string // pcx-...
	Region      string
}

// PeeringExposures finds private VPCs reachable from an internet-exposed VPC over
// an active peering. It requires a route to the peering on BOTH sides (so a
// bidirectional TCP path genuinely exists, not just a one-way send), and that the
// private side has no internet gateway of its own (else it is directly exposed
// and covered elsewhere). Pure and safe on nil state.
func PeeringExposures(a *state.AWS) []PeeringExposure {
	if a == nil {
		return nil
	}
	hasIGW := map[string]bool{}                  // vpc -> has its own internet-gateway route
	routesToPeer := map[string]map[string]bool{} // vpc -> set of pcx it routes to
	for _, rt := range a.RouteTables {
		if rt.VPCID == "" {
			continue
		}
		if rt.IGWRoute {
			hasIGW[rt.VPCID] = true
		}
		for _, pcx := range rt.PeeringIDs {
			if routesToPeer[rt.VPCID] == nil {
				routesToPeer[rt.VPCID] = map[string]bool{}
			}
			routesToPeer[rt.VPCID][pcx] = true
		}
	}

	var out []PeeringExposure
	seen := map[string]bool{}
	for _, p := range a.Peerings {
		if !p.Active || p.VPCA == "" || p.VPCB == "" {
			continue
		}
		for _, dir := range [][2]string{{p.VPCA, p.VPCB}, {p.VPCB, p.VPCA}} {
			src, dst := dir[0], dir[1]
			if hasIGW[src] && !hasIGW[dst] && routesToPeer[src][p.ID] && routesToPeer[dst][p.ID] {
				key := p.ID + "|" + dst
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, PeeringExposure{
					PrivateVPC: dst, InternetVPC: src, PeeringID: p.ID, Region: p.Region,
				})
			}
		}
	}
	return out
}

// SGTransitiveExposure is a security group reachable from the internet because
// it admits a source group that is itself world-open: exposure chains inward one
// hop. It carries one entry per (target group, world-open source group, ports).
type SGTransitiveExposure struct {
	SecurityGroup string
	SGName        string
	Region        string
	SourceSG      string
	SourceName    string
	Ports         string
}

// TransitiveWorldOpenSGs returns the groups reachable one hop from the internet
// via a world-open source group. A group that is itself world-open is excluded
// (it is directly exposed). Pure and safe on nil state. Shared by the check and
// the attack-path graph so the relationship has one definition.
func TransitiveWorldOpenSGs(a *state.AWS) []SGTransitiveExposure {
	if a == nil {
		return nil
	}
	worldOpen := map[string]state.SecurityGroup{}
	for _, sg := range a.SecurityGroups {
		if sg.WorldOpen() {
			worldOpen[sg.ID] = sg
		}
	}
	if len(worldOpen) == 0 {
		return nil
	}
	var out []SGTransitiveExposure
	seen := map[string]bool{}
	for _, sg := range a.SecurityGroups {
		if sg.WorldOpen() {
			continue
		}
		for _, r := range sg.Ingress {
			for _, srcID := range r.SourceSGs {
				src, ok := worldOpen[srcID]
				if !ok {
					continue
				}
				key := sg.ID + "|" + srcID + "|" + portRange(r)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, SGTransitiveExposure{
					SecurityGroup: sg.ID, SGName: sg.Name, Region: sg.Region,
					SourceSG: srcID, SourceName: src.Name, Ports: portRange(r),
				})
			}
		}
	}
	return out
}

// VPCLateralExposure is a private VPC reachable from an internet-exposed VPC
// across a network bridge: a peering connection or a transit gateway. It unifies
// the two bridge types so the rule-level solver and the graph treat them alike.
type VPCLateralExposure struct {
	PrivateVPC  string
	InternetVPC string
	Via         string // "peering" | "transit-gateway"
	ViaID       string // pcx-... | tgw-...
	Region      string
}

// VPCLateralExposures returns every private VPC reachable from an internet-exposed
// VPC, across either a peering connection or a transit gateway. Pure and safe on
// nil state.
func VPCLateralExposures(a *state.AWS) []VPCLateralExposure {
	var out []VPCLateralExposure
	for _, e := range PeeringExposures(a) {
		out = append(out, VPCLateralExposure{
			PrivateVPC: e.PrivateVPC, InternetVPC: e.InternetVPC, Via: "peering", ViaID: e.PeeringID, Region: e.Region,
		})
	}
	out = append(out, tgwExposures(a)...)
	return out
}

// tgwExposures finds private VPCs reachable from an internet-exposed VPC over a
// shared transit gateway: both VPCs have an available attachment to the gateway
// and a route table that routes to it, the internet side has its own IGW route,
// and the private side does not. Transit-gateway route-table segmentation is not
// modeled, so a gateway whose route tables isolate attachments is reported
// conservatively (the VPC-route requirement on both sides is the gate applied).
func tgwExposures(a *state.AWS) []VPCLateralExposure {
	if a == nil {
		return nil
	}
	hasIGW := map[string]bool{}
	routesToTGW := map[string]map[string]bool{}
	for _, rt := range a.RouteTables {
		if rt.VPCID == "" {
			continue
		}
		if rt.IGWRoute {
			hasIGW[rt.VPCID] = true
		}
		for _, tgw := range rt.TransitGatewayIDs {
			if routesToTGW[rt.VPCID] == nil {
				routesToTGW[rt.VPCID] = map[string]bool{}
			}
			routesToTGW[rt.VPCID][tgw] = true
		}
	}
	byTGW := map[string][]state.TGWAttachment{}
	for _, att := range a.TGWAttachments {
		if att.Available && att.TgwID != "" && att.VPCID != "" {
			byTGW[att.TgwID] = append(byTGW[att.TgwID], att)
		}
	}

	var out []VPCLateralExposure
	seen := map[string]bool{}
	for tgw, atts := range byTGW {
		for _, src := range atts {
			if !hasIGW[src.VPCID] || !routesToTGW[src.VPCID][tgw] {
				continue
			}
			for _, dst := range atts {
				if dst.VPCID == src.VPCID || hasIGW[dst.VPCID] || !routesToTGW[dst.VPCID][tgw] {
					continue
				}
				key := tgw + "|" + dst.VPCID
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, VPCLateralExposure{
					PrivateVPC: dst.VPCID, InternetVPC: src.VPCID, Via: "transit-gateway", ViaID: tgw, Region: dst.Region,
				})
			}
		}
	}
	return out
}

// SGPeerExposure is a security group in a private VPC that admits a CIDR
// overlapping an internet-exposed peer VPC's range, reachable across a bridge
// (peering or transit gateway). The group's own rule looks like ordinary
// internal access (a 10.x source, not 0.0.0.0/0), but the source range is the
// internet-facing peer, so a host there can reach this group on the admitted ports.
type SGPeerExposure struct {
	SecurityGroup string
	SGName        string
	Region        string
	PrivateVPC    string
	InternetVPC   string
	Via           string // "peering" | "transit-gateway"
	ViaID         string // pcx-... | tgw-...
	MatchedCIDR   string // the group's ingress CIDR that overlaps the peer VPC
	PeerCIDR      string // the internet-exposed peer VPC CIDR it overlaps
	Ports         string // ports the matching rule admits
}

// SGPeerReachable finds security groups reachable from an internet-exposed VPC at
// the rule level: for each private VPC reachable across a bridge (peering or
// transit gateway), it returns the groups in that VPC whose non-world ingress
// admits a CIDR overlapping the internet-exposed peer's VPC range. World-open
// rules are skipped (covered by the direct-exposure check). Pure and safe on nil.
func SGPeerReachable(a *state.AWS) []SGPeerExposure {
	if a == nil {
		return nil
	}
	exposures := VPCLateralExposures(a)
	if len(exposures) == 0 {
		return nil
	}
	vpcCIDR := map[string][]string{}
	for _, v := range a.VPCs {
		vpcCIDR[v.ID] = v.CIDRs
	}

	var out []SGPeerExposure
	seen := map[string]bool{}
	for _, ex := range exposures {
		peerCIDRs := vpcCIDR[ex.InternetVPC]
		if len(peerCIDRs) == 0 {
			continue // without the peer's range there is nothing to match against
		}
		for _, sg := range a.SecurityGroups {
			if sg.VPCID != ex.PrivateVPC {
				continue
			}
			for _, r := range sg.Ingress {
				if r.OpenV4 || r.OpenV6 {
					continue // world-open is direct exposure, covered elsewhere
				}
				ruleCIDRs := append(append([]string{}, r.IPv4CIDRs...), r.IPv6CIDRs...)
				matched, peer := firstOverlap(ruleCIDRs, peerCIDRs)
				if matched == "" {
					continue
				}
				key := sg.ID + "|" + ex.ViaID + "|" + matched + "|" + portRange(r)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, SGPeerExposure{
					SecurityGroup: sg.ID, SGName: sg.Name, Region: sg.Region,
					PrivateVPC: ex.PrivateVPC, InternetVPC: ex.InternetVPC, Via: ex.Via, ViaID: ex.ViaID,
					MatchedCIDR: matched, PeerCIDR: peer, Ports: portRange(r),
				})
			}
		}
	}
	return out
}

// firstOverlap returns the first (ruleCIDR, peerCIDR) pair that overlaps, or
// ("","") if none do.
func firstOverlap(ruleCIDRs, peerCIDRs []string) (string, string) {
	for _, rc := range ruleCIDRs {
		for _, pc := range peerCIDRs {
			if cidrsOverlap(rc, pc) {
				return rc, pc
			}
		}
	}
	return "", ""
}

// cidrsOverlap reports whether two CIDRs share any address: either network
// contains the other's base address. Unparseable or cross-family pairs do not
// overlap.
func cidrsOverlap(a, b string) bool {
	_, na, err := net.ParseCIDR(a)
	if err != nil {
		return false
	}
	_, nb, err := net.ParseCIDR(b)
	if err != nil {
		return false
	}
	return na.Contains(nb.IP) || nb.Contains(na.IP)
}

// portRange renders a rule's admitted ports for evidence.
func portRange(r state.IngressRule) string {
	if r.Protocol == "-1" || (r.FromPort == 0 && r.ToPort == 65535) {
		return "all ports"
	}
	if r.FromPort == r.ToPort {
		return fmt.Sprintf("port %d", r.FromPort)
	}
	return fmt.Sprintf("ports %d-%d", r.FromPort, r.ToPort)
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
