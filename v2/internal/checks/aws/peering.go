package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/reachability"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(vpcPeeringLateralExposure{}) }

// vpcPeeringLateralExposure flags a private VPC (no internet gateway of its own)
// that is reachable from an internet-exposed VPC across an active peering
// connection with routes on both sides. The exposure is topological: each VPC
// looks fine in isolation, but a foothold in the internet-facing VPC can pivot
// over the peering into the private one. A per-resource or per-VPC config scan
// misses it because the path spans two VPCs.
type vpcPeeringLateralExposure struct{}

func (vpcPeeringLateralExposure) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:          "aws_vpc_peering_lateral_exposure",
		Title:       "Private VPC is reachable from an internet-exposed VPC via peering",
		Provider:    "aws",
		Service:     "vpc",
		Severity:    findings.SeverityMedium,
		Rationale:   "A VPC with no internet gateway of its own is not directly exposed, but an active peering with routes on both sides to an internet-facing VPC bridges the two: a foothold in the internet-facing VPC can pivot across the peering and reach hosts in the private VPC. The path is invisible to a scan that judges each VPC in isolation.",
		Impact:      "An attacker who gains a foothold in the internet-exposed VPC can move laterally over the peering into the private VPC and reach resources presumed unreachable from outside.",
		Remediation: "Confirm the peering and its routes are required; scope the peered route to the specific subnets/CIDRs that must communicate (not the whole VPC), and rely on security groups/NACLs to restrict cross-VPC traffic rather than a blanket peering route.",
		References:  []string{"https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html"},
	}
}

func (c vpcPeeringLateralExposure) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, e := range reachability.PeeringExposures(st.AWS) {
		res := findings.Resource{
			ID: e.PrivateVPC, Name: e.PrivateVPC, Type: "aws_vpc", Provider: "aws", Region: e.Region,
		}
		desc := fmt.Sprintf("VPC %s has no internet gateway of its own but is reachable from internet-exposed VPC %s across active peering %s (routes exist on both sides). A foothold in %s can pivot over the peering into %s.",
			e.PrivateVPC, e.InternetVPC, e.PeeringID, e.InternetVPC, e.PrivateVPC)
		poc := fmt.Sprintf("aws ec2 describe-route-tables --filters Name=route.vpc-peering-connection-id,Values=%s --query 'RouteTables[].VpcId'", e.PeeringID)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
