package validate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// roundTripFunc lets a test stand in an http transport without real network I/O.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func s3WithResponse(status int, body string) *s3PublicRead {
	return &s3PublicRead{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// Assert the request is anonymous (no Authorization header) and a GET.
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			return nil, errors.New("validator issued a non-anonymous or non-GET request")
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}}
}

func s3Finding(bucket string) findings.Finding {
	return findings.Finding{CheckID: "aws_s3_public_access", Resource: findings.Resource{ID: bucket}}
}

func TestS3ValidatorConfirmedOn200(t *testing.T) {
	v := s3WithResponse(http.StatusOK, "<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>")
	ev, err := v.Validate(context.Background(), s3Finding("public-bucket"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("200 should confirm, got %+v", ev)
	}
	if ev.Vantage != findings.VantageExternal {
		t.Fatalf("expected external vantage, got %s", ev.Vantage)
	}
	if !strings.Contains(ev.Request, "anonymous") {
		t.Fatalf("request description should note anonymous access: %q", ev.Request)
	}
}

func TestS3ValidatorUnconfirmedOn403(t *testing.T) {
	v := s3WithResponse(http.StatusForbidden, "<Error><Code>AccessDenied</Code></Error>")
	ev, err := v.Validate(context.Background(), s3Finding("maybe-bucket"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictUnconfirmed {
		t.Fatalf("403 should be unconfirmed (not refuted), got %+v", ev)
	}
}

func TestS3ValidatorBlockedOnNetworkError(t *testing.T) {
	v := &s3PublicRead{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: timeout")
	})}}
	ev, err := v.Validate(context.Background(), s3Finding("unreachable"))
	if err != nil {
		t.Fatalf("network error should be captured as evidence, not returned: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictBlocked {
		t.Fatalf("network failure should be blocked, got %+v", ev)
	}
}

func TestS3ValidatorEmptyBucketNoOp(t *testing.T) {
	v := s3WithResponse(http.StatusOK, "")
	ev, err := v.Validate(context.Background(), s3Finding(""))
	if err != nil || ev != nil {
		t.Fatalf("empty bucket id should be a no-op, got ev=%+v err=%v", ev, err)
	}
}

func TestS3ValidatorBodyTruncated(t *testing.T) {
	big := strings.Repeat("A", 5000)
	v := s3WithResponse(http.StatusOK, big)
	ev, _ := v.Validate(context.Background(), s3Finding("b"))
	if ev == nil {
		t.Fatal("expected evidence")
	}
	// Evidence response embeds at most maxEvidenceBody body bytes (plus framing).
	if len(ev.Response) > maxEvidenceBody+64 {
		t.Fatalf("evidence response not truncated: %d bytes", len(ev.Response))
	}
}

func TestS3ValidatorContractMetadata(t *testing.T) {
	v := &s3PublicRead{}
	if v.CheckID() != "aws_s3_public_access" {
		t.Fatalf("unexpected check id %q", v.CheckID())
	}
	if v.BlastRadius() != BlastRadiusNone {
		t.Fatalf("s3 validator must declare blast radius none, got %q", v.BlastRadius())
	}
}
