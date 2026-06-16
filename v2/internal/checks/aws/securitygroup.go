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
	worldOpen := map[string]state.SecurityGroup{}
	for _, sg := range st.AWS.SecurityGroups {
		if sg.WorldOpen() {
			worldOpen[sg.ID] = sg
		}
	}
	if len(worldOpen) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	var out []findings.Finding
	for _, sg := range st.AWS.SecurityGroups {
		if sg.WorldOpen() {
			continue // directly exposed; aws_ec2_open_ingress already covers it
		}
		sources := worldOpenSourceRefs(sg, worldOpen)
		if len(sources) == 0 {
			continue
		}
		res := findings.Resource{
			ID: sg.ID, Name: sg.Name, Type: "aws_security_group", Provider: "aws", Region: sg.Region,
		}
		desc := fmt.Sprintf("Security group %s (%s) admits source group(s) %s that are open to the internet, so a host reachable through them can reach hosts in this group even though it has no world-open rule.",
			sg.Name, sg.ID, strings.Join(sources, ", "))
		poc := fmt.Sprintf("aws ec2 describe-security-groups --group-ids %s --query 'SecurityGroups[].IpPermissions'", sg.ID)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

// worldOpenSourceRefs returns labels for the world-open source groups a group's
// ingress references (deduped, sorted), each annotated with the ports it admits.
func worldOpenSourceRefs(sg state.SecurityGroup, worldOpen map[string]state.SecurityGroup) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range sg.Ingress {
		for _, srcID := range r.SourceSGs {
			src, ok := worldOpen[srcID]
			if !ok {
				continue
			}
			label := fmt.Sprintf("%s (%s) on %s", src.Name, srcID, portLabel(r))
			if _, dup := seen[label]; dup {
				continue
			}
			seen[label] = struct{}{}
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// portLabel renders the port range a rule admits for human-readable evidence.
func portLabel(r state.IngressRule) string {
	if isAllPorts(r) {
		return "all ports"
	}
	if r.FromPort == r.ToPort {
		return fmt.Sprintf("port %d", r.FromPort)
	}
	return fmt.Sprintf("ports %d-%d", r.FromPort, r.ToPort)
}
