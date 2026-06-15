package validate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func init() { Register(&dnsDangling{}) }

// dnsDangling confirms a flagged dangling-DNS / subdomain-takeover candidate from
// the operator's external network vantage — no credentials, exactly what an
// internet attacker sees.
//
// The proof is read-only and stops at the claimable primitive (blast radius
// none): it resolves the delegation target and, if needed, issues a single
// unauthenticated GET to the subdomain to read the service's own "this name is
// unclaimed" response. It never registers the target, never writes — it only
// observes that the door is open.
//
// Verdicts:
//   - confirmed   — the delegation target does not resolve (NXDOMAIN), or the
//     subdomain serves a known service "unclaimed" fingerprint (e.g. S3
//     NoSuchBucket). The name is genuinely dangling/claimable.
//   - unconfirmed — the target resolves and the subdomain serves ordinary
//     content with no takeover marker: live from this vantage, not refuted
//     (a single external vantage cannot prove the target is *yours*).
//   - blocked     — DNS/HTTP could not be reached from this vantage (timeout).
type dnsDangling struct {
	// resolve and client are injectable for tests; they default to the system
	// resolver and a short-timeout HTTP client.
	resolve func(ctx context.Context, host string) ([]string, error)
	client  *http.Client
}

func (*dnsDangling) CheckID() string           { return "aws_route53_dangling_record" }
func (*dnsDangling) BlastRadius() string       { return BlastRadiusNone }
func (*dnsDangling) Vantage() findings.Vantage { return findings.VantageExternal }

func (v *dnsDangling) Validate(ctx context.Context, _ Env, f findings.Finding) (*findings.Evidence, error) {
	target := strings.TrimSuffix(strings.ToLower(f.Resource.Endpoint), ".")
	host := strings.TrimSuffix(strings.ToLower(f.Resource.Name), ".")
	if target == "" {
		return nil, nil // no delegation target captured — nothing to confirm
	}

	resolve := v.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}

	// Step 1: does the delegation target still exist? NXDOMAIN is the strongest,
	// universal dangling signal — the record points at nothing, so whoever can
	// re-register that target name owns the subdomain.
	reqDesc := "DNS resolve " + target
	if _, err := resolve(ctx, target); err != nil {
		switch {
		case isNXDOMAIN(err):
			return dnsEvidence(reqDesc,
				"NXDOMAIN — delegation target does not resolve; the subdomain is dangling and the target is claimable",
				VerdictConfirmed), nil
		case isTimeout(err):
			return dnsEvidence(reqDesc, "DNS timeout ("+err.Error()+"); could not resolve from this vantage", VerdictBlocked), nil
		default:
			// SERVFAIL / temporary / other — neither a clean NXDOMAIN nor a success.
			return dnsEvidence(reqDesc, "DNS error ("+err.Error()+"); inconclusive — does not refute the finding", VerdictUnconfirmed), nil
		}
	}

	// Step 2: the target resolves, but it may be a live AWS endpoint serving a
	// service "unclaimed" page (the classic S3 case: s3.amazonaws.com resolves
	// fine while the specific bucket is gone). Read the subdomain's own response.
	if host == "" {
		host = target
	}
	return v.fingerprint(ctx, host)
}

// fingerprint issues one unauthenticated GET to the subdomain and looks for a
// service-specific "this name is unclaimed" marker in the response.
func (v *dnsDangling) fingerprint(ctx context.Context, host string) (*findings.Evidence, error) {
	client := v.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	url := "https://" + host + "/"
	reqDesc := "GET " + url + "  (anonymous, unsigned)"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("validate dns %s: %w", host, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if isTimeout(err) {
			return dnsEvidence(reqDesc, "request timeout ("+err.Error()+"); could not reach the subdomain from this vantage", VerdictBlocked), nil
		}
		return dnsEvidence(reqDesc, "request error ("+err.Error()+"); inconclusive — does not refute the finding", VerdictUnconfirmed), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxEvidenceBody))
	bodyStr := strings.TrimSpace(string(body))

	if marker, ok := takeoverFingerprint(bodyStr); ok {
		return dnsEvidence(reqDesc,
			fmt.Sprintf("HTTP %d; matched takeover marker %q — target endpoint is unclaimed and registrable", resp.StatusCode, marker),
			VerdictConfirmed), nil
	}
	// The subdomain answered with ordinary content and no unclaimed marker. From a
	// single external vantage that is not a refutation, but it is not a confirmed
	// takeover either — the operator should verify ownership of the live target.
	return dnsEvidence(reqDesc,
		fmt.Sprintf("HTTP %d; no takeover marker (target serves content) — live from this vantage, ownership unverified", resp.StatusCode),
		VerdictUnconfirmed), nil
}

// takeoverFingerprints are high-confidence "this endpoint is unclaimed" response
// markers. Kept narrow: only markers that mean the target name is registrable by
// anyone, not generic 404s that a live site can also return.
var takeoverFingerprints = []string{
	"NoSuchBucket",                        // S3 (REST/XML)
	"The specified bucket does not exist", // S3 (website)
}

// takeoverFingerprint reports the first unclaimed-endpoint marker found in body.
func takeoverFingerprint(body string) (string, bool) {
	for _, m := range takeoverFingerprints {
		if strings.Contains(body, m) {
			return m, true
		}
	}
	return "", false
}

// dnsEvidence builds an external-vantage evidence record for the DNS validator.
func dnsEvidence(req, resp, verdict string) *findings.Evidence {
	return &findings.Evidence{
		Vantage:    findings.VantageExternal,
		Request:    req,
		Response:   resp,
		Verdict:    verdict,
		CapturedAt: time.Now().UTC(),
	}
}

// isNXDOMAIN reports whether err is an authoritative "no such host" DNS answer,
// as opposed to a timeout or temporary failure.
func isNXDOMAIN(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}
