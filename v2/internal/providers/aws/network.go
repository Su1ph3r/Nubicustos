package aws

import (
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// collectNetworkTopology gathers the subnet + route-table topology the
// reachability solver needs: which subnet each resource sits in, and whether
// that subnet's route table has a default route to an internet gateway.
func collectNetworkTopology(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	explicit := collectRouteTables(sc, client, region, st)
	collectSubnets(sc, client, region, st, explicit)
	collectVPCPeerings(sc, client, region, st)
}

// collectRouteTables records each route table (main flag + whether it routes a
// default to an internet gateway) and returns the explicit subnet->routeTable
// association map so subnets can resolve their effective table.
func collectRouteTables(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) map[string]string {
	explicit := map[string]string{} // subnetID -> routeTableID

	pager := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return explicit
		}
		for _, rt := range page.RouteTables {
			id := awssdk.ToString(rt.RouteTableId)
			entry := state.RouteTable{ID: id, Region: region, VPCID: awssdk.ToString(rt.VpcId)}
			for _, assoc := range rt.Associations {
				if awssdk.ToBool(assoc.Main) {
					entry.Main = true
				}
				if sid := awssdk.ToString(assoc.SubnetId); sid != "" {
					explicit[sid] = id
				}
			}
			seenPeer := map[string]bool{}
			for _, route := range rt.Routes {
				if routesToIGW(route) {
					entry.IGWRoute = true
				}
				if pcx := awssdk.ToString(route.VpcPeeringConnectionId); pcx != "" && !seenPeer[pcx] {
					seenPeer[pcx] = true
					entry.PeeringIDs = append(entry.PeeringIDs, pcx)
				}
			}
			st.AddRouteTable(entry)
		}
	}
	return explicit
}

// routesToIGW reports whether a route sends a default route to an internet gateway.
func routesToIGW(r ec2types.Route) bool {
	defaultRoute := awssdk.ToString(r.DestinationCidrBlock) == "0.0.0.0/0" ||
		awssdk.ToString(r.DestinationIpv6CidrBlock) == "::/0"
	return defaultRoute && strings.HasPrefix(awssdk.ToString(r.GatewayId), "igw-")
}

// collectVPCPeerings records the active VPC-peering connections in the region:
// the two VPCs each bridges. Combined with route tables that target a peering,
// the reachability solver can find a private VPC reachable from an internet-
// exposed one across the peering.
func collectVPCPeerings(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	pager := ec2.NewDescribeVpcPeeringConnectionsPaginator(client, &ec2.DescribeVpcPeeringConnectionsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, pcx := range page.VpcPeeringConnections {
			active := false
			if pcx.Status != nil {
				active = pcx.Status.Code == ec2types.VpcPeeringConnectionStateReasonCodeActive
			}
			st.AddVPCPeering(state.VPCPeering{
				ID:     awssdk.ToString(pcx.VpcPeeringConnectionId),
				Region: region,
				VPCA:   vpcInfoID(pcx.RequesterVpcInfo),
				VPCB:   vpcInfoID(pcx.AccepterVpcInfo),
				Active: active,
			})
		}
	}
}

// vpcInfoID safely reads the VpcId from a peering-connection VPC-info side.
func vpcInfoID(info *ec2types.VpcPeeringConnectionVpcInfo) string {
	if info == nil {
		return ""
	}
	return awssdk.ToString(info.VpcId)
}

// collectSubnets records each subnet's VPC, public-IP-on-launch flag, and the
// route table it is explicitly associated with (empty => the solver falls back
// to the VPC's main route table).
func collectSubnets(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State, explicit map[string]string) {
	pager := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, sn := range page.Subnets {
			id := awssdk.ToString(sn.SubnetId)
			st.AddSubnet(state.Subnet{
				ID:                  id,
				Region:              region,
				VPCID:               awssdk.ToString(sn.VpcId),
				RouteTableID:        explicit[id],
				MapPublicIPOnLaunch: awssdk.ToBool(sn.MapPublicIpOnLaunch),
			})
		}
	}
}
