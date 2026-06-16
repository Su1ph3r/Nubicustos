package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(classicELBInsecureListener{}) }

type classicELBInsecureListener struct{}

func (classicELBInsecureListener) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_elb_classic_insecure_listener", Title: "Classic load balancer has a cleartext (HTTP/TCP) listener",
		Provider: "aws", Service: "elb", Severity: findings.SeverityMedium,
		Rationale:   "A classic ELB front-end listener using HTTP or TCP terminates traffic in cleartext, so credentials, cookies, and data in transit can be intercepted — especially on an internet-facing balancer.",
		Impact:      "Traffic to the load balancer can be observed or tampered with on the network path.",
		Remediation: "Use an HTTPS/SSL listener with an ACM certificate (or migrate to an ALB/NLB with TLS): aws elb create-load-balancer-listeners --load-balancer-name <name> --listeners Protocol=HTTPS,...",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c classicELBInsecureListener) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, e := range st.AWS.ClassicELBs {
		if len(e.InsecurePorts) == 0 {
			continue
		}
		res := findings.Resource{ID: e.Name, Name: e.Name, Type: "aws_elb_classic", Provider: "aws", Region: e.Region}
		scheme := "internal"
		if e.InternetFacing {
			scheme = "internet-facing"
		}
		desc := fmt.Sprintf("Classic load balancer %q (%s, %s) has cleartext listener(s) on port(s) %v.", e.Name, e.Region, scheme, e.InsecurePorts)
		poc := fmt.Sprintf("aws elb describe-load-balancers --load-balancer-names %s --region %s --query 'LoadBalancerDescriptions[].ListenerDescriptions[].Listener.Protocol'", e.Name, e.Region)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
