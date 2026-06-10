package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&vpcCollector{}) }

type vpcCollector struct{}

func (vpcCollector) Name() string { return "aws:vpc" }

// Collect enumerates VPCs per region and marks which ones have a flow log,
// cross-referencing DescribeFlowLogs (whose ResourceId is the VPC id for
// VPC-level flow logs).
func (vpcCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := ec2.NewFromConfig(sc.AWS, func(o *ec2.Options) { o.Region = region })

		flowLogged := map[string]bool{}
		flPager := ec2.NewDescribeFlowLogsPaginator(client, &ec2.DescribeFlowLogsInput{})
		for flPager.HasMorePages() {
			page, err := flPager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, fl := range page.FlowLogs {
				if rid := awssdk.ToString(fl.ResourceId); rid != "" {
					flowLogged[rid] = true
				}
			}
		}

		vpcPager := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
		for vpcPager.HasMorePages() {
			page, err := vpcPager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, v := range page.Vpcs {
				id := awssdk.ToString(v.VpcId)
				st.AddVPC(state.VPCInfo{ID: id, Region: region, HasFlowLog: flowLogged[id]})
			}
		}
	}
	return nil
}
