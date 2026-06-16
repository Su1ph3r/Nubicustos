package aws

import (
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(classicELBCollector{}) }

type classicELBCollector struct{}

func (classicELBCollector) Name() string { return "aws:elb-classic" }

// Collect gathers classic (v1) load balancer listener posture per region,
// recording front-end listeners using cleartext HTTP/TCP. Per-region failures
// are tolerated.
func (classicELBCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := elb.NewFromConfig(sc.AWS, func(o *elb.Options) { o.Region = region })
		p := elb.NewDescribeLoadBalancersPaginator(client, &elb.DescribeLoadBalancersInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, lb := range page.LoadBalancerDescriptions {
				name := awssdk.ToString(lb.LoadBalancerName)
				if name == "" {
					continue
				}
				e := state.ClassicELB{
					Name:           name,
					Region:         region,
					InternetFacing: strings.EqualFold(awssdk.ToString(lb.Scheme), "internet-facing"),
				}
				for _, ld := range lb.ListenerDescriptions {
					if ld.Listener == nil {
						continue
					}
					if isCleartextProto(awssdk.ToString(ld.Listener.Protocol)) {
						e.InsecurePorts = append(e.InsecurePorts, ld.Listener.LoadBalancerPort)
					}
				}
				st.AddClassicELB(e)
			}
		}
	}
	return nil
}

// isCleartextProto reports whether a classic-ELB front-end protocol is
// unencrypted (HTTP or TCP, as opposed to HTTPS or SSL).
func isCleartextProto(proto string) bool {
	switch strings.ToUpper(proto) {
	case "HTTP", "TCP":
		return true
	default:
		return false
	}
}
