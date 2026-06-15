package aws

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(route53DanglingRecord{}) }

// route53DanglingRecord flags DNS records that delegate to a takeover-prone
// cloud-service endpoint (S3, CloudFront, Elastic Beanstalk, API Gateway). These
// are *candidates*: a record pointing at a live endpoint is fine, but if the
// target has been deprovisioned the subdomain dangles and an attacker can often
// re-register the target name and serve content under the victim's domain.
//
// Like the RDS-public check (config flags the candidate; the TCP validator
// confirms reachability), this check asserts the at-risk shape and leaves
// runtime confirmation to the opt-in subdomain-takeover validator (§9.1), which
// resolves the target and reports confirmed / unconfirmed / blocked.
type route53DanglingRecord struct{}

func (route53DanglingRecord) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:        "aws_route53_dangling_record",
		Title:     "Route53 record delegates to a takeover-prone target",
		Provider:  "aws",
		Service:   "route53",
		Severity:  findings.SeverityMedium,
		Rationale: "A CNAME or alias pointing at a cloud-service endpoint becomes a subdomain-takeover vector the moment that endpoint is deprovisioned: the name still resolves to a service that anyone can re-register.",
		Impact:    "An attacker who claims the abandoned target serves arbitrary content (phishing, cookie theft, OAuth-redirect abuse) under the victim's trusted subdomain.",
		Remediation: "Confirm the target still exists; if it does not, delete the dangling record:\n" +
			"aws route53 change-resource-record-sets --hosted-zone-id <zone> --change-batch '{\"Changes\":[{\"Action\":\"DELETE\",...}]}'",
		References: []string{
			"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
			"https://github.com/EdOverflow/can-i-take-over-xyz",
		},
	}
}

func (c route53DanglingRecord) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()

	var out []findings.Finding
	for _, r := range st.AWS.Route53Records {
		service, ok := takeoverService(r.Target)
		if !ok {
			continue
		}

		host := strings.TrimSuffix(r.Name, ".")
		res := findings.Resource{
			ID:       host,
			Name:     host,
			Type:     "aws_route53_record",
			Provider: "aws",
			Account:  st.AWS.Account,
			Region:   "global",
			// Endpoint carries the delegation target so the takeover validator can
			// resolve it without re-deriving alias targets from DNS (alias records
			// hide their AWS target behind transparent Route53 resolution).
			Endpoint: r.Target,
		}

		kind := "CNAME"
		if r.Alias {
			kind = "alias " + r.Type
		}
		desc := fmt.Sprintf("%s record %q delegates to %s (%s) — a takeover-prone target. Run with --validate to confirm whether the target is dangling/claimable.",
			kind, host, r.Target, service)
		poc := fmt.Sprintf("dig +short %s; curl -sS -o /dev/null -w '%%{http_code}\\n' https://%s/", host, host)

		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// takeoverServiceSuffixes maps a takeover-prone hostname suffix to the service
// name. Kept deliberately narrow (high-signal endpoints) to avoid flagging
// healthy delegations to non-claimable targets.
var takeoverServiceSuffixes = []struct{ suffix, service string }{
	{".cloudfront.net", "CloudFront"},
	{".elasticbeanstalk.com", "Elastic Beanstalk"},
	{".s3-website", "S3 website"}, // matches s3-website.<region>. and s3-website-<region>.
	{".s3.amazonaws.com", "S3"},
	{".amazonaws.com", "S3/regional endpoint"}, // catch-all for *.s3.<region>.amazonaws.com, execute-api, etc. (checked last)
}

// takeoverService classifies a delegation target. More specific suffixes are
// matched before the broad amazonaws.com catch-all so the service label is
// precise; the catch-all only fires for S3 regional and API Gateway shapes.
func takeoverService(target string) (string, bool) {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, s := range takeoverServiceSuffixes {
		if s.suffix == ".amazonaws.com" {
			// Only treat the broad suffix as takeover-prone for the known claimable
			// shapes, not every AWS endpoint (e.g. an ELB DNS name is not claimable).
			if (strings.Contains(t, ".s3.") || strings.Contains(t, ".s3-")) && strings.HasSuffix(t, ".amazonaws.com") {
				return "S3 regional endpoint", true
			}
			if strings.Contains(t, ".execute-api.") && strings.HasSuffix(t, ".amazonaws.com") {
				return "API Gateway", true
			}
			continue
		}
		if strings.HasSuffix(t, s.suffix) || strings.Contains(t, s.suffix) {
			return s.service, true
		}
	}
	return "", false
}
