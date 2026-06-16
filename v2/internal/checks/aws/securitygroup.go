package aws

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/reachability"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(sgTransitiveWorldOpen{})
	engine.RegisterCheck(sgPeerReachableExposure{})
}

// sgPeerReachableExposure flags a security group in a private VPC whose ingress
// admits a CIDR that overlaps an internet-exposed peer VPC's range, reachable
// across an active peering. This is the resource-level form of the VPC peering
// finding: the group's rule looks like ordinary internal access (a private CIDR,
// not 0.0.0.0/0), but that range is the internet-facing peer, so a host there
// can reach this group. A per-rule scan treats the private CIDR as benign.
type sgPeerReachableExposure struct{}

func (sgPeerReachableExposure) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:          "aws_sg_peer_reachable_exposure",
		Title:       "Security group admits a CIDR reachable from an internet-exposed peer VPC",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    findings.SeverityHigh,
		Rationale:   "An ingress rule allowing a private CIDR reads as benign internal access, but when that CIDR is the range of a peered VPC that itself reaches the internet, the rule is an internet-pivot path: a host in the peer VPC (reachable from outside) can reach this group across the peering. The exposure is only visible once the group's source CIDR is matched against the peer VPC's range and the peering topology.",
		Impact:      "An attacker who gains a foothold in the internet-exposed peer VPC can reach this group on the admitted ports, despite the group having no world-open rule.",
		Remediation: "Narrow the ingress to the specific hosts that must communicate rather than the whole peer VPC range, confirm the peering is required, and segment internet-facing peer VPCs from those holding sensitive resources.",
		References:  []string{"https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html"},
	}
}

func (c sgPeerReachableExposure) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, e := range reachability.SGPeerReachable(st.AWS) {
		res := findings.Resource{
			ID: e.SecurityGroup, Name: e.SGName, Type: "aws_security_group", Provider: "aws", Region: e.Region,
		}
		desc := fmt.Sprintf("Security group %s (%s) in VPC %s admits %s on %s, which overlaps the range %s of internet-exposed peer VPC %s (across active peering %s). A host in %s can reach this group even though it has no world-open rule.",
			e.SGName, e.SecurityGroup, e.PrivateVPC, e.MatchedCIDR, e.Ports, e.PeerCIDR, e.InternetVPC, e.PeeringID, e.InternetVPC)
		poc := fmt.Sprintf("aws ec2 describe-security-groups --group-ids %s --query 'SecurityGroups[].IpPermissions'", e.SecurityGroup)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

// sgTransitiveWorldOpen flags a security group that is not itself world-open but
// admits a source security group that IS open to the internet. Internet exposure
// chains inward: a host reachable through the world-open group can reach hosts in
// this one. A per-rule scan that only looks for 0.0.0.0/0 on the group itself
// misses this, because the group's own rules look closed.
type sgTransitiveWorldOpen struct{}

func (sgTransitiveWorldOpen) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:          "aws_sg_transitive_world_open",
		Title:       "Security group is reachable from the internet via a world-open source group",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    findings.SeverityMedium,
		Rationale:   "A security group whose ingress allows another group that is itself open to 0.0.0.0/0 inherits that exposure one hop removed: an attacker who reaches a host in the world-open group can then reach hosts in this one. The group's own rules reference only another group, so it reads as closed in isolation.",
		Impact:      "An attacker who compromises a host in the internet-facing group can pivot to hosts in this group on the referenced ports, despite this group having no world-open rule.",
		Remediation: "Confirm the source group must be internet-facing; if not, restrict its 0.0.0.0/0 rules. Otherwise tighten this group's rule to the specific ports the source tier needs, and segment internet-facing tiers from internal ones.",
	}
}

func (c sgTransitiveWorldOpen) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	// Group the (target, world-open source) pairs from the shared solver by target
	// group, so each exposed group is one finding listing its world-open sources.
	type group struct {
		res     findings.Resource
		sources map[string]struct{}
	}
	byTarget := map[string]*group{}
	var order []string
	for _, e := range reachability.TransitiveWorldOpenSGs(st.AWS) {
		g, ok := byTarget[e.SecurityGroup]
		if !ok {
			g = &group{
				res:     findings.Resource{ID: e.SecurityGroup, Name: e.SGName, Type: "aws_security_group", Provider: "aws", Region: e.Region},
				sources: map[string]struct{}{},
			}
			byTarget[e.SecurityGroup] = g
			order = append(order, e.SecurityGroup)
		}
		g.sources[fmt.Sprintf("%s (%s) on %s", e.SourceName, e.SourceSG, e.Ports)] = struct{}{}
	}

	now := time.Now().UTC()
	var out []findings.Finding
	for _, id := range order {
		g := byTarget[id]
		labels := make([]string, 0, len(g.sources))
		for l := range g.sources {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		desc := fmt.Sprintf("Security group %s (%s) admits source group(s) %s that are open to the internet, so a host reachable through them can reach hosts in this group even though it has no world-open rule.",
			g.res.Name, g.res.ID, strings.Join(labels, ", "))
		poc := fmt.Sprintf("aws ec2 describe-security-groups --group-ids %s --query 'SecurityGroups[].IpPermissions'", g.res.ID)
		out = append(out, findings.New(c.Spec(), g.res, desc, poc, now))
	}
	return out, nil
}
