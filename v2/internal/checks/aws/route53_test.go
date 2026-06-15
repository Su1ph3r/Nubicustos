package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

// TestDanglingRecordFlagsTakeoverProneTargets proves the check flags only the
// records that delegate to a claimable cloud-service endpoint, and carries the
// target through to Resource.Endpoint for the validator.
func TestDanglingRecordFlagsTakeoverProneTargets(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("123456789012")

	st.AddRoute53Record(state.Route53Record{Zone: "example.com.", Name: "app.example.com.", Type: "CNAME", Target: "my-old-bucket.s3-website-us-east-1.amazonaws.com"})
	st.AddRoute53Record(state.Route53Record{Zone: "example.com.", Name: "cdn.example.com.", Type: "A", Target: "d111abcdef8.cloudfront.net", Alias: true})
	st.AddRoute53Record(state.Route53Record{Zone: "example.com.", Name: "api.example.com.", Type: "CNAME", Target: "abc123.execute-api.us-east-1.amazonaws.com"})
	// Not takeover-prone: a CNAME to a third-party SaaS not in the fingerprint set.
	st.AddRoute53Record(state.Route53Record{Zone: "example.com.", Name: "blog.example.com.", Type: "CNAME", Target: "ghs.googlehosted.com"})
	// Not takeover-prone: an alias to an ELB DNS name (not anonymously claimable).
	st.AddRoute53Record(state.Route53Record{Zone: "example.com.", Name: "lb.example.com.", Type: "A", Target: "my-lb-123.us-east-1.elb.amazonaws.com", Alias: true})

	fs, err := route53DanglingRecord{}.Evaluate(nil, st)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(fs) != 3 {
		var got []string
		for _, f := range fs {
			got = append(got, f.Resource.Name)
		}
		t.Fatalf("expected 3 findings (s3 website, cloudfront, api gateway), got %d: %v", len(fs), got)
	}

	gotHosts := map[string]string{} // host -> endpoint(target)
	for _, f := range fs {
		if f.CheckID != "aws_route53_dangling_record" {
			t.Errorf("unexpected check id %q", f.CheckID)
		}
		if f.Resource.Endpoint == "" {
			t.Errorf("finding for %s missing Endpoint (target) for the validator", f.Resource.Name)
		}
		gotHosts[f.Resource.Name] = f.Resource.Endpoint
	}
	for _, want := range []string{"app.example.com", "cdn.example.com", "api.example.com"} {
		if _, ok := gotHosts[want]; !ok {
			t.Errorf("expected a finding for %s, got hosts %v", want, gotHosts)
		}
	}
	for _, notWant := range []string{"blog.example.com", "lb.example.com"} {
		if _, ok := gotHosts[notWant]; ok {
			t.Errorf("did not expect a finding for %s (not anonymously claimable)", notWant)
		}
	}
}

func TestTakeoverServiceClassification(t *testing.T) {
	cases := map[string]bool{
		"x.s3-website-us-east-1.amazonaws.com":  true,
		"x.s3.amazonaws.com":                    true,
		"x.s3.eu-west-1.amazonaws.com":          true,
		"d1.cloudfront.net":                     true,
		"env.us-east-1.elasticbeanstalk.com":    true,
		"a.execute-api.us-east-1.amazonaws.com": true,
		"my-lb.us-east-1.elb.amazonaws.com":     false,
		"ghs.googlehosted.com":                  false,
		"example.org":                           false,
		"":                                      false,
	}
	for target, want := range cases {
		if _, ok := takeoverService(target); ok != want {
			t.Errorf("takeoverService(%q) ok=%v, want %v", target, ok, want)
		}
	}
}
