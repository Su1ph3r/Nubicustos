package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&elbv2Collector{}) }

type elbv2Collector struct{}

func (elbv2Collector) Name() string { return "aws:elbv2" }

// Collect gathers ALB/NLB posture per region: scheme (internet-facing), each
// listener's protocol/TLS policy, and whether access logging is enabled.
func (elbv2Collector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := elbv2.NewFromConfig(sc.AWS, func(o *elbv2.Options) { o.Region = region })
		pager := elbv2.NewDescribeLoadBalancersPaginator(client, &elbv2.DescribeLoadBalancersInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, lb := range page.LoadBalancers {
				arn := awssdk.ToString(lb.LoadBalancerArn)
				record := state.LoadBalancer{
					ARN:               arn,
					Name:              awssdk.ToString(lb.LoadBalancerName),
					Region:            region,
					InternetFacing:    lb.Scheme == elbv2types.LoadBalancerSchemeEnumInternetFacing,
					Listeners:         collectListeners(sc, client, arn),
					AccessLogsEnabled: accessLogsEnabled(sc, client, arn),
				}
				st.AddLoadBalancer(record)
			}
		}
	}
	return nil
}

func collectListeners(sc *engine.ScanContext, client *elbv2.Client, lbARN string) []state.ELBListener {
	out, err := client.DescribeListeners(sc.Ctx, &elbv2.DescribeListenersInput{LoadBalancerArn: &lbARN})
	if err != nil {
		return nil
	}
	var listeners []state.ELBListener
	for _, l := range out.Listeners {
		listeners = append(listeners, state.ELBListener{
			Protocol:  string(l.Protocol),
			Port:      int(awssdk.ToInt32(l.Port)),
			SSLPolicy: awssdk.ToString(l.SslPolicy),
		})
	}
	return listeners
}

func accessLogsEnabled(sc *engine.ScanContext, client *elbv2.Client, lbARN string) bool {
	out, err := client.DescribeLoadBalancerAttributes(sc.Ctx, &elbv2.DescribeLoadBalancerAttributesInput{LoadBalancerArn: &lbARN})
	if err != nil {
		return false
	}
	for _, a := range out.Attributes {
		if awssdk.ToString(a.Key) == "access_logs.s3.enabled" {
			return awssdk.ToString(a.Value) == "true"
		}
	}
	return false
}
