package pubscan

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// roundTripFunc stands in an HTTP transport so tests issue no real network I/O.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func httpResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

// fakeClient routes anonymous GETs: list requests return the listing XML; object
// GETs return their mapped body (keyed by URL path). It asserts every request is
// an anonymous GET.
func fakeClient(t *testing.T, listing string, objects map[string]string) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Fatalf("pubscan issued a non-anonymous or non-GET request: %s %s", r.Method, r.URL)
		}
		if strings.Contains(r.URL.RawQuery, "list-type") {
			return httpResp(http.StatusOK, listing), nil
		}
		if body, ok := objects[r.URL.Path]; ok {
			return httpResp(http.StatusOK, body), nil
		}
		return httpResp(http.StatusNotFound, ""), nil
	})}
}

func publicBucket(name string) state.AWS {
	return state.AWS{S3Buckets: []state.S3Bucket{{Name: name, Region: "us-east-1", ACLPublic: true}}}
}

func listingXML(entries ...[2]string) string {
	var b strings.Builder
	b.WriteString("<ListBucketResult>")
	for _, e := range entries {
		b.WriteString("<Contents><Key>" + e[0] + "</Key><Size>" + e[1] + "</Size></Contents>")
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

// synthetic, clearly-fake AWS credential material (never a real key).
const (
	fakeKeyID  = "AKIAPUBLICOBJECT0001"
	fakeSecret = "abcD1234efGH5678ijKL9012mnOP3456qrST7890"
)

// captureSink records AddAWSKey calls for assertions.
type captureSink struct {
	keys []struct{ id, secret, surface, resource string }
}

func (c *captureSink) AddAWSKey(id, secret, _, surface, resource, _ string) {
	c.keys = append(c.keys, struct{ id, secret, surface, resource string }{id, secret, surface, resource})
}

func TestScan_DetectsAWSKeyInPublicObject(t *testing.T) {
	a := publicBucket("leaky")
	content := "[default]\naws_access_key_id = " + fakeKeyID + "\naws_secret_access_key = " + fakeSecret + "\n"
	client := fakeClient(t,
		listingXML([2]string{"creds.txt", "120"}),
		map[string]string{"/creds.txt": content})

	sink := &captureSink{}
	out := Scan(context.Background(), &a, sink, Options{HTTPClient: client})

	if len(out) != 1 {
		t.Fatalf("expected 1 leak finding, got %d", len(out))
	}
	f := out[0]
	if f.CheckID != CheckID || f.Severity != findings.SeverityCritical {
		t.Fatalf("finding check/sev = %s/%s, want %s/critical", f.CheckID, f.Severity, CheckID)
	}
	if f.Resource.ID != "s3://leaky/creds.txt" {
		t.Errorf("resource id = %q", f.Resource.ID)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Verdict != "confirmed" {
		t.Fatalf("expected confirmed evidence, got %+v", f.Evidence)
	}
	// Privacy invariant: the raw secret must never appear in the finding.
	blob := f.Description + f.Evidence[0].Response + f.Evidence[0].Request + f.PoC
	if strings.Contains(blob, fakeSecret) || strings.Contains(blob, fakeKeyID) {
		t.Errorf("finding leaked raw secret material: %q", blob)
	}
	if !strings.Contains(f.Evidence[0].Response, "0001") { // masked last-4 only
		t.Errorf("evidence should carry the masked key: %q", f.Evidence[0].Response)
	}
	// The raw pair must reach the capture sink for liveness/chain.
	if len(sink.keys) != 1 || sink.keys[0].id != fakeKeyID || sink.keys[0].secret != fakeSecret {
		t.Fatalf("capture sink did not receive the raw pair: %+v", sink.keys)
	}
	if sink.keys[0].surface != "s3_public_object" || sink.keys[0].resource != "leaky/creds.txt" {
		t.Errorf("captured key surface/resource = %q/%q", sink.keys[0].surface, sink.keys[0].resource)
	}
}

func TestScan_NoSecretNoFinding(t *testing.T) {
	a := publicBucket("benign")
	client := fakeClient(t,
		listingXML([2]string{"readme.txt", "20"}),
		map[string]string{"/readme.txt": "just some public docs, nothing secret here"})
	out := Scan(context.Background(), &a, nil, Options{HTTPClient: client})
	if len(out) != 0 {
		t.Fatalf("benign content should yield no findings, got %d", len(out))
	}
}

func TestScan_SkipsNonPublicBuckets(t *testing.T) {
	a := state.AWS{S3Buckets: []state.S3Bucket{
		{Name: "private", Region: "us-east-1"}, // neither ACLPublic nor PolicyPublic
	}}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("non-public bucket must not be contacted: %s", r.URL)
		return nil, nil
	})}
	if out := Scan(context.Background(), &a, nil, Options{HTTPClient: client}); len(out) != 0 {
		t.Fatalf("expected no findings, got %d", len(out))
	}
}

func TestScan_SkipsOversizedObjectByListedSize(t *testing.T) {
	a := publicBucket("big")
	// Listed size exceeds the per-object cap, so the object is never downloaded.
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.RawQuery, "list-type") {
			return httpResp(http.StatusOK, listingXML([2]string{"huge.bin", "999999999"})), nil
		}
		t.Fatalf("oversized object must not be downloaded: %s", r.URL)
		return nil, nil
	})}
	if out := Scan(context.Background(), &a, nil, Options{HTTPClient: client, MaxObjectBytes: 1024}); len(out) != 0 {
		t.Fatalf("expected no findings for skipped oversized object, got %d", len(out))
	}
}

func TestScan_ListForbiddenYieldsNothing(t *testing.T) {
	a := publicBucket("denied")
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return httpResp(http.StatusForbidden, "<Error/>"), nil
	})}
	if out := Scan(context.Background(), &a, nil, Options{HTTPClient: client}); len(out) != 0 {
		t.Fatalf("list-denied bucket should yield nothing, got %d", len(out))
	}
}

func TestScan_TotalBudgetStopsScanning(t *testing.T) {
	a := publicBucket("budget")
	content := "aws_access_key_id = " + fakeKeyID + " secret = " + fakeSecret
	client := fakeClient(t,
		listingXML([2]string{"a.txt", "80"}, [2]string{"b.txt", "80"}),
		map[string]string{"/a.txt": content, "/b.txt": content})
	// Budget smaller than a single object body: the first read consumes it; the
	// second object is not scanned.
	out := Scan(context.Background(), &a, nil, Options{HTTPClient: client, TotalByteBudget: 10})
	if len(out) > 1 {
		t.Fatalf("total budget should cap scanning to one object, got %d findings", len(out))
	}
}

func TestScan_NilStateSafe(t *testing.T) {
	if out := Scan(context.Background(), nil, nil, Options{}); out != nil {
		t.Fatalf("nil state should yield nil, got %v", out)
	}
}
