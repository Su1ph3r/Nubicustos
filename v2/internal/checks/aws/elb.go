package aws

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(elbInsecureListener{})
	engine.RegisterCheck(elbWeakTLS{})
	engine.RegisterCheck(elbAccessLogs{})
}

func lbResource(account string, lb state.LoadBalancer) findings.Resource {
	res := regionalResource(account, lb.Region, lb.Name, "aws_lb", lb.ARN)
	return res
}

// isWeakTLSPolicy reports whether an ELB SSL negotiation policy permits TLS 1.0
// or 1.1 (or is one of the legacy catch-all policies).
func isWeakTLSPolicy(p string) bool {
	if p == "" {
		return false
	}
	if strings.Contains(p, "TLS-1-0") || strings.Contains(p, "TLS-1-1") {
		return true
	}
	switch p {
	case "ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08":
		return true
	}
	return false
}

// --- insecure (plaintext) listener ------------------------------------------

type elbInsecureListener struct{}

func (elbInsecureListener) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_elb_insecure_listener", Title: "Internet-facing load balancer has a plaintext HTTP listener",
		Provider: "aws", Service: "elb", Severity: findings.SeverityMedium,
		Rationale:   "A plaintext HTTP listener on an internet-facing load balancer transmits traffic unencrypted and is open to interception.",
		Impact:      "Credentials and data in transit can be intercepted or modified by a network attacker.",
		Remediation: "Serve over HTTPS and redirect HTTP to HTTPS: add an HTTPS listener with an ACM certificate and a redirect rule.",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC09-BP02"}},
	}
}

func (c elbInsecureListener) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, lb := range st.AWS.LoadBalancers {
		if !lb.InternetFacing {
			continue
		}
		var ports []string
		for _, l := range lb.Listeners {
			if strings.EqualFold(l.Protocol, "HTTP") {
				ports = append(ports, fmt.Sprintf("%d", l.Port))
			}
		}
		if len(ports) == 0 {
			continue
		}
		desc := fmt.Sprintf("Internet-facing load balancer %q in %s has plaintext HTTP listener(s) on port(s) %s.",
			lb.Name, lb.Region, strings.Join(ports, ", "))
		poc := fmt.Sprintf("aws elbv2 describe-listeners --load-balancer-arn %s", lb.ARN)
		out = append(out, findings.New(spec, lbResource(st.AWS.Account, lb), desc, poc, now))
	}
	return out, nil
}

// --- weak TLS policy --------------------------------------------------------

type elbWeakTLS struct{}

func (elbWeakTLS) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_elb_weak_tls_policy", Title: "Load balancer listener uses a weak TLS policy",
		Provider: "aws", Service: "elb", Severity: findings.SeverityMedium,
		Rationale:   "TLS 1.0/1.1 negotiation policies are deprecated and vulnerable to known downgrade and protocol weaknesses.",
		Impact:      "Clients can negotiate weak TLS versions, undermining transport security.",
		Remediation: "Use a modern policy, e.g.: aws elbv2 modify-listener --listener-arn <arn> --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC09-BP02"}},
	}
}

func (c elbWeakTLS) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, lb := range st.AWS.LoadBalancers {
		var weak []string
		for _, l := range lb.Listeners {
			if isWeakTLSPolicy(l.SSLPolicy) {
				weak = append(weak, fmt.Sprintf("%d (%s)", l.Port, l.SSLPolicy))
			}
		}
		if len(weak) == 0 {
			continue
		}
		desc := fmt.Sprintf("Load balancer %q in %s has listener(s) with a weak TLS policy: %s.",
			lb.Name, lb.Region, strings.Join(weak, ", "))
		poc := fmt.Sprintf("aws elbv2 describe-listeners --load-balancer-arn %s --query 'Listeners[].SslPolicy'", lb.ARN)
		out = append(out, findings.New(spec, lbResource(st.AWS.Account, lb), desc, poc, now))
	}
	return out, nil
}

// --- access logs ------------------------------------------------------------

type elbAccessLogs struct{}

func (elbAccessLogs) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_elb_access_logs_disabled", Title: "Load balancer access logs are disabled",
		Provider: "aws", Service: "elb", Severity: findings.SeverityLow,
		Rationale:   "Access logs record request-level detail needed to investigate abuse and reconstruct attacks against the application.",
		Impact:      "Without access logs there is no request-level record to investigate application-layer attacks.",
		Remediation: "Enable access logs: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <arn> --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket>",
	}
}

func (c elbAccessLogs) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, lb := range st.AWS.LoadBalancers {
		if lb.AccessLogsEnabled {
			continue
		}
		desc := fmt.Sprintf("Load balancer %q in %s does not have access logging enabled.", lb.Name, lb.Region)
		poc := fmt.Sprintf("aws elbv2 describe-load-balancer-attributes --load-balancer-arn %s", lb.ARN)
		out = append(out, findings.New(spec, lbResource(st.AWS.Account, lb), desc, poc, now))
	}
	return out, nil
}
