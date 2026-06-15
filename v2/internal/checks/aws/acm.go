package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// expiryWarnDays is the window within which a still-valid certificate is flagged
// as expiring soon.
const expiryWarnDays = 30

func init() {
	engine.RegisterCheck(acmExpired{})
	engine.RegisterCheck(acmExpiring{})
}

func certResource(account string, c state.Certificate) findings.Resource {
	res := regionalResource(account, c.Region, c.DomainName, "aws_acm_certificate", c.ARN)
	if res.ID == "" {
		res.ID = c.ARN
	}
	return res
}

// --- expired ----------------------------------------------------------------

type acmExpired struct{}

func (acmExpired) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_acm_certificate_expired", Title: "ACM certificate has expired",
		Provider: "aws", Service: "acm", Severity: findings.SeverityHigh,
		Rationale:   "An expired certificate breaks TLS for clients and may force insecure fallbacks or outages.",
		Impact:      "Clients receive certificate errors; services depending on the certificate fail or are bypassed insecurely.",
		Remediation: "Renew or replace the certificate and re-bind it to the listener/distribution that uses it.",
		PoC:         "aws acm describe-certificate --certificate-arn <arn> --query 'Certificate.[Status,NotAfter]'",
	}
}

func (c acmExpired) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cert := range st.AWS.Certificates {
		if !cert.Expired {
			continue
		}
		desc := fmt.Sprintf("ACM certificate for %q in %s has expired (status %s).", cert.DomainName, cert.Region, cert.Status)
		out = append(out, findings.New(spec, certResource(st.AWS.Account, cert), desc, spec.PoC, now))
	}
	return out, nil
}

// --- expiring soon ----------------------------------------------------------

type acmExpiring struct{}

func (acmExpiring) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_acm_certificate_expiring", Title: "ACM certificate is expiring soon",
		Provider: "aws", Service: "acm", Severity: findings.SeverityMedium,
		Rationale:   "A certificate nearing expiry risks an outage if renewal (especially for imported certs) is not completed in time.",
		Impact:      "If not renewed, TLS will break for clients when the certificate expires.",
		Remediation: "Ensure managed renewal is eligible, or renew/re-import the certificate before it expires.",
		PoC:         "aws acm describe-certificate --certificate-arn <arn> --query 'Certificate.NotAfter'",
	}
}

func (c acmExpiring) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cert := range st.AWS.Certificates {
		if cert.Expired || cert.NotAfter.IsZero() || cert.DaysToExpiry > expiryWarnDays {
			continue
		}
		desc := fmt.Sprintf("ACM certificate for %q in %s expires in %d day(s).", cert.DomainName, cert.Region, cert.DaysToExpiry)
		out = append(out, findings.New(spec, certResource(st.AWS.Account, cert), desc, spec.PoC, now))
	}
	return out, nil
}
