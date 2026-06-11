package validate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func init() { Register(&s3PublicRead{}) }

// s3PublicRead confirms a flagged-public S3 bucket by attempting an anonymous
// (unsigned, credential-free) ListObjectsV2 from the operator's network vantage.
// A 200 proves unauthenticated listing is genuinely possible; a 403 means the
// bucket exists but anonymous listing is denied (the policy/ACL flag may still
// permit object reads, so the verdict is unconfirmed, not refuted). It never
// writes or deletes — blast radius none.
type s3PublicRead struct {
	client *http.Client
}

func (*s3PublicRead) CheckID() string     { return "aws_s3_public_access" }
func (*s3PublicRead) BlastRadius() string { return BlastRadiusNone }

// maxEvidenceBody bounds captured response bytes so evidence stays small and
// secret-safe (a listing is not secret, but truncation is the safe default).
const maxEvidenceBody = 512

func (v *s3PublicRead) Validate(ctx context.Context, _ Env, f findings.Finding) (*findings.Evidence, error) {
	bucket := f.Resource.ID
	if bucket == "" {
		return nil, nil
	}
	client := v.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	// Virtual-hosted-style anonymous list, capped to a single key.
	url := fmt.Sprintf("https://%s.s3.amazonaws.com/?list-type=2&max-keys=1", bucket)
	reqDesc := "GET " + url + "  (anonymous, unsigned)"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("validate s3 %s: %w", bucket, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network failure / timeout: we could not reach the target — blocked, not refuted.
		return &findings.Evidence{
			Vantage:    findings.VantageExternal,
			Request:    reqDesc,
			Response:   "request error: " + err.Error(),
			Verdict:    VerdictBlocked,
			CapturedAt: time.Now().UTC(),
		}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxEvidenceBody))

	ev := &findings.Evidence{
		Vantage:    findings.VantageExternal,
		Request:    reqDesc,
		Response:   fmt.Sprintf("HTTP %d; body[:%d]=%q", resp.StatusCode, len(body), strings.TrimSpace(string(body))),
		CapturedAt: time.Now().UTC(),
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		ev.Verdict = VerdictConfirmed
	case resp.StatusCode == http.StatusForbidden:
		// Exists but anonymous list denied; object-level public read may still
		// apply, so this neither confirms nor refutes the finding.
		ev.Verdict = VerdictUnconfirmed
	default:
		ev.Verdict = VerdictUnconfirmed
	}
	return ev, nil
}
