package validate

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// httpStub returns a client whose transport answers every GET with the given
// status and body (roundTripFunc is shared with s3_test.go).
func httpStub(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
}

func dnsFinding(host, target string) findings.Finding {
	return findings.Finding{
		CheckID:  "aws_route53_dangling_record",
		Resource: findings.Resource{Name: host, Endpoint: target},
	}
}

func TestDNSDanglingVerdicts(t *testing.T) {
	nxdomain := func(_ context.Context, host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	resolves := func(_ context.Context, _ string) ([]string, error) {
		return []string{"203.0.113.10"}, nil
	}
	dnsTimeout := func(_ context.Context, _ string) ([]string, error) {
		return nil, timeoutErr{}
	}

	tests := []struct {
		name        string
		resolve     func(context.Context, string) ([]string, error)
		client      *http.Client
		target      string
		wantVerdict string
		wantSubstr  string
	}{
		{
			name:        "target NXDOMAIN is a confirmed dangling takeover",
			resolve:     nxdomain,
			target:      "my-old-bucket.s3-website-us-east-1.amazonaws.com",
			wantVerdict: VerdictConfirmed,
			wantSubstr:  "NXDOMAIN",
		},
		{
			name:        "target resolves but subdomain serves S3 NoSuchBucket is confirmed",
			resolve:     resolves,
			client:      httpStub(404, "<Error><Code>NoSuchBucket</Code></Error>"),
			target:      "live-bucket.s3.amazonaws.com",
			wantVerdict: VerdictConfirmed,
			wantSubstr:  "NoSuchBucket",
		},
		{
			name:        "target resolves and subdomain serves ordinary content is unconfirmed",
			resolve:     resolves,
			client:      httpStub(200, "<html>welcome</html>"),
			target:      "live-bucket.s3.amazonaws.com",
			wantVerdict: VerdictUnconfirmed,
			wantSubstr:  "no takeover marker",
		},
		{
			name:        "DNS timeout is blocked, not refuted",
			resolve:     dnsTimeout,
			target:      "whatever.cloudfront.net",
			wantVerdict: VerdictBlocked,
			wantSubstr:  "timeout",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &dnsDangling{resolve: tc.resolve, client: tc.client}
			ev, err := v.Validate(context.Background(), Env{}, dnsFinding("app.example.com", tc.target))
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if ev == nil {
				t.Fatalf("expected evidence, got nil")
			}
			if ev.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (response: %s)", ev.Verdict, tc.wantVerdict, ev.Response)
			}
			if !strings.Contains(ev.Response, tc.wantSubstr) {
				t.Errorf("response %q does not contain %q", ev.Response, tc.wantSubstr)
			}
			if ev.Vantage != findings.VantageExternal {
				t.Errorf("vantage = %q, want external", ev.Vantage)
			}
		})
	}
}

// TestDNSDanglingNoTargetSkips proves a finding without a captured target is
// skipped (nil, nil) rather than guessed at.
func TestDNSDanglingNoTargetSkips(t *testing.T) {
	v := &dnsDangling{
		resolve: func(context.Context, string) ([]string, error) { return nil, nil },
	}
	ev, err := v.Validate(context.Background(), Env{}, dnsFinding("app.example.com", ""))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev != nil {
		t.Fatalf("expected nil evidence for missing target, got %+v", ev)
	}
}

// TestDNSDanglingRegistered proves the validator is wired into the registry and
// declares the safe, external contract.
func TestDNSDanglingRegistered(t *testing.T) {
	v := &dnsDangling{}
	if v.BlastRadius() != BlastRadiusNone {
		t.Errorf("blast radius = %q, want none", v.BlastRadius())
	}
	if v.Vantage() != findings.VantageExternal {
		t.Errorf("vantage = %q, want external", v.Vantage())
	}
	if v.CheckID() != "aws_route53_dangling_record" {
		t.Errorf("check id = %q", v.CheckID())
	}
}
