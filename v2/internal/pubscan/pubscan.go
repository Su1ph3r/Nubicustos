// Package pubscan turns a public-bucket config assertion into runtime proof of
// an active leak. A stateless scanner can say "this bucket is public"; it cannot
// say "this public bucket is right now serving an object that contains a live
// AWS key." pubscan does the latter: it anonymously (credential-free, from the
// operator's vantage) samples the objects of each public bucket and runs the
// control-plane secret detector over their actual content.
//
// Safety contract (this package reads target object content, so the bounds are
// strict and explicit):
//   - Read-only. GET and anonymous ListObjectsV2 only, never write, delete, or
//     mutate. It is opt-in (the scan flag --scan-public-content); the default
//     scan performs zero object reads.
//   - Bounded. A per-bucket object cap, a per-object byte cap (objects larger
//     than the cap are skipped via their listed size, never downloaded), and a
//     total byte budget across the whole run, so a malicious or huge bucket can
//     never make the scanner read unbounded data.
//   - Privacy-careful. Only masked detections leave this package: the secret
//     detector drops raw values at its boundary, and findings carry the masked
//     rendering, a secret-safe locator, and the object key, never the content.
//     An object with no detection produces nothing, so benign content is neither
//     reported nor retained.
//
// When a capture sink is supplied (--capture-secrets), recovered raw AWS key
// pairs are added to it so the liveness and attack-chain passes can confirm and
// escalate them, extending the flagship chain to "public object -> live key ->
// privesc." Raw material reaches only the in-process sink, never a finding or
// the store.
package pubscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// CheckID is the stable id of the public-object-leak finding.
const CheckID = "aws_s3_public_object_secret"

// SecretSink receives raw AWS key pairs recovered from public object content
// (the in-process --capture-secrets store). Implemented by *secrets.Capture;
// nil-safe so capture-off is the zero value. Kept as an interface so the package
// does not hard-depend on a concrete capture type.
type SecretSink interface {
	AddAWSKey(accessKeyID, secretAccessKey, sessionToken, surface, resource, region string)
}

// Options bounds the scan. Zero values fall back to conservative defaults.
type Options struct {
	MaxObjectsPerBucket int          // objects sampled per bucket (default 20)
	MaxObjectBytes      int64        // per-object download cap (default 256 KiB)
	TotalByteBudget     int64        // total bytes across the whole run (default 16 MiB)
	HTTPClient          *http.Client // override for tests; default 10s-timeout client
}

func (o *Options) withDefaults() {
	if o.MaxObjectsPerBucket <= 0 {
		o.MaxObjectsPerBucket = 20
	}
	if o.MaxObjectBytes <= 0 {
		o.MaxObjectBytes = 256 << 10
	}
	if o.TotalByteBudget <= 0 {
		o.TotalByteBudget = 16 << 20
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// objectMeta is one listed object's key and size.
type objectMeta struct {
	Key  string `xml:"Key"`
	Size int64  `xml:"Size"`
}

type listResult struct {
	XMLName  xml.Name     `xml:"ListBucketResult"`
	Contents []objectMeta `xml:"Contents"`
}

// Scan samples the public buckets in a and returns one finding per object found
// serving secret material. It is safe on nil state and never panics on a bucket
// it cannot reach (that bucket is simply skipped). sink, when non-nil, receives
// recovered raw AWS key pairs for downstream liveness/chain analysis.
func Scan(ctx context.Context, a *state.AWS, sink SecretSink, opts Options) []findings.Finding {
	if a == nil {
		return nil
	}
	opts.withDefaults()
	now := time.Now().UTC()

	var out []findings.Finding
	var spent int64
	for _, b := range a.S3Buckets {
		if spent >= opts.TotalByteBudget {
			break
		}
		if !isPublic(b) {
			continue
		}
		objs := listObjects(ctx, opts.HTTPClient, b, opts.MaxObjectsPerBucket)
		for _, o := range objs {
			if spent >= opts.TotalByteBudget {
				break
			}
			if o.Key == "" || o.Size == 0 || o.Size > opts.MaxObjectBytes {
				continue // empty, or too large to sample without exceeding the per-object cap
			}
			body, n := getObject(ctx, opts.HTTPClient, b, o.Key, opts.MaxObjectBytes)
			spent += n
			if len(body) == 0 {
				continue
			}
			content := string(body)
			matches := secrets.Scan(content, "s3://"+b.Name+"/"+o.Key)
			if len(matches) == 0 {
				continue
			}
			out = append(out, leakFinding(b, o.Key, matches, now))
			// Recover raw AWS key pairs so the liveness/chain passes can act on
			// them. Conservative pairing (exactly one key id) lives in secrets.
			if sink != nil {
				for _, k := range secrets.PairAWSKeysText(content) {
					sink.AddAWSKey(k.AccessKeyID, k.SecretAccessKey, k.SessionToken,
						"s3_public_object", b.Name+"/"+o.Key, b.Region)
				}
			}
		}
	}
	return out
}

// isPublic mirrors the graph's public-bucket predicate: flagged public by ACL or
// policy and not fully shielded by Block Public Access.
func isPublic(b state.S3Bucket) bool {
	return (b.ACLPublic || b.PolicyPublic) && !b.FullyBlocked()
}

// listObjects performs an anonymous, bounded ListObjectsV2 and returns the listed
// objects (empty on any error: an unreachable or list-denied bucket yields no
// content sample rather than a failure).
func listObjects(ctx context.Context, client *http.Client, b state.S3Bucket, max int) []objectMeta {
	u := fmt.Sprintf("%s/?list-type=2&max-keys=%d", bucketEndpoint(b), max)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Cap the listing body too: a list of <max> keys is small, but never trust
	// the peer to bound it.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var lr listResult
	if err := xml.Unmarshal(data, &lr); err != nil {
		return nil
	}
	if len(lr.Contents) > max {
		lr.Contents = lr.Contents[:max]
	}
	return lr.Contents
}

// getObject anonymously GETs one object, reading at most limit bytes. It returns
// the body and the number of bytes read (for the total-budget accounting), and
// empty on any error.
func getObject(ctx context.Context, client *http.Client, b state.S3Bucket, key string, limit int64) ([]byte, int64) {
	ou := &url.URL{Scheme: "https", Host: bucketHost(b), Path: "/" + key}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ou.String(), nil)
	if err != nil {
		return nil, 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return body, int64(len(body))
}

// bucketHost returns the virtual-hosted host for a bucket, region-qualified when
// the region is known (and not the global default), so S3 does not 301-redirect.
func bucketHost(b state.S3Bucket) string {
	if b.Region != "" && b.Region != "us-east-1" {
		return b.Name + ".s3." + b.Region + ".amazonaws.com"
	}
	return b.Name + ".s3.amazonaws.com"
}

func bucketEndpoint(b state.S3Bucket) string { return "https://" + bucketHost(b) }

// leakFinding builds the runtime-proof finding for one object serving secrets.
// An exposed cloud credential (an AWS access key) is critical, directly
// actionable; any other secret class is high.
func leakFinding(b state.S3Bucket, key string, matches []secrets.Match, now time.Time) findings.Finding {
	sev := findings.SeverityHigh
	for _, m := range matches {
		if m.Detector == "aws_access_key_id" {
			sev = findings.SeverityCritical
			break
		}
	}

	res := findings.Resource{
		ID:       "s3://" + b.Name + "/" + key,
		Name:     key,
		Type:     "aws_s3_object",
		Provider: "aws",
		Region:   b.Region,
		ARN:      "arn:aws:s3:::" + b.Name + "/" + key,
	}

	ev := findings.Evidence{
		Vantage:    findings.VantageExternal,
		Request:    fmt.Sprintf("GET %s/%s  (anonymous, unsigned)", bucketEndpoint(b), key),
		Response:   "object served anonymously and contains: " + describe(matches),
		Verdict:    "confirmed",
		CapturedAt: now,
	}

	return findings.Finding{
		ID:          CheckID + "::" + res.ID,
		CheckID:     CheckID,
		Title:       "Public S3 object is serving secret material",
		Severity:    sev,
		Status:      findings.StatusOpen,
		Provider:    "aws",
		Service:     "s3",
		Resource:    res,
		Description: fmt.Sprintf("Object %q in public bucket %q was read anonymously and contains %s. This is a confirmed active leak: anyone on the internet can retrieve the credential right now, not a hypothetical exposure.", key, b.Name, describe(matches)),
		Rationale:   "A public bucket is only a potential problem until an object in it is shown to actually serve secret material to an unauthenticated caller. Reading the object proves the leak is live.",
		Impact:      "Any internet user can download the object and use the embedded credential; an exposed AWS key can be exercised immediately against the account.",
		Remediation: fmt.Sprintf("Remove or rotate the leaked secret, delete or restrict the object, and apply Block Public Access to bucket %q so objects cannot be read anonymously.", b.Name),
		PoC:         fmt.Sprintf("aws s3 cp s3://%s/%s - --no-sign-request | head   # served without credentials", b.Name, key),
		Reachable:   findings.ReachYes,
		Evidence:    []findings.Evidence{ev},
		FirstSeen:   now,
		LastSeen:    now,
	}
}

// describe renders the masked detections as a secret-safe summary, deduped and
// ordered for stable output.
func describe(matches []secrets.Match) string {
	seen := map[string]struct{}{}
	var parts []string
	for _, m := range matches {
		s := fmt.Sprintf("%s (%s)", m.Kind, m.Masked)
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
