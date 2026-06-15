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
			for _, route := range rt.Routes {
				if routesToIGW(route) {
					entry.IGWRoute = true
					break
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
