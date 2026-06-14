package validate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
)

// fakeProber drives the liveness validator: it returns a verdict (and optional
// error) per access key id.
type fakeProber struct {
	live    map[string]string // access key id -> ARN (live)
	blocked map[string]bool   // access key id -> probe could not complete
	seen    []string
}

func (p *fakeProber) WhoAmI(_ context.Context, c secrets.AWSKeyCredential) (WhoAmIResult, error) {
	p.seen = append(p.seen, c.AccessKeyID)
	if p.blocked[c.AccessKeyID] {
		return WhoAmIResult{}, errors.New("dial tcp: timeout")
	}
	if arn, ok := p.live[c.AccessKeyID]; ok {
		return WhoAmIResult{ARN: arn, Account: "111122223333", Live: true}, nil
	}
	return WhoAmIResult{Live: false}, nil // rejected
}

func exposedFinding() findings.Finding {
	return findings.Finding{CheckID: "aws_exposed_secret", Resource: findings.Resource{Account: "111122223333"}}
}

func TestLivenessNoCaptureReturnsNil(t *testing.T) {
	v := &exposedSecretLiveness{}
	ev, err := v.Validate(context.Background(), Env{}, exposedFinding())
	if err != nil || ev != nil {
		t.Fatalf("with no captured keys, expected (nil,nil), got (%v,%v)", ev, err)
	}
}

func TestLivenessConfirmedWhenAnyKeyLive(t *testing.T) {
	prober := &fakeProber{live: map[string]string{"AKIALIVE000000000001": "arn:aws:iam::111122223333:user/deploy"}}
	env := Env{
		AWSKeyProber: prober,
		CapturedAWSKeys: []secrets.AWSKeyCredential{
			{AccessKeyID: "AKIALIVE000000000001", SecretAccessKey: "s", Surface: "lambda_env", Resource: "fn"},
			{AccessKeyID: "AKIADEAD000000000002", SecretAccessKey: "s", Surface: "ec2_userdata", Resource: "i-1"},
		},
	}
	ev, err := (&exposedSecretLiveness{}).Validate(context.Background(), env, exposedFinding())
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("expected a confirmed evidence, got %+v", ev)
	}
	if !strings.Contains(ev.Response, "arn:aws:iam::111122223333:user/deploy") {
		t.Errorf("evidence should name the live identity: %q", ev.Response)
	}
	if !strings.Contains(ev.Response, "1/2 captured AWS key(s) live") {
		t.Errorf("evidence should tally results: %q", ev.Response)
	}
	if ev.Vantage != findings.VantageAuthenticated {
		t.Errorf("vantage = %q, want authenticated", ev.Vantage)
	}
	// Hard invariant: no raw secret material ("s") in the evidence, only masked.
	if strings.Contains(ev.Request, "SecretAccessKey") || strings.Contains(ev.Response, ": s") {
		t.Errorf("evidence must not leak raw secrets: req=%q resp=%q", ev.Request, ev.Response)
	}
	if !strings.Contains(ev.Request, "****0001") {
		t.Errorf("evidence should reference keys by masked id: %q", ev.Request)
	}
}

func TestLivenessUnconfirmedWhenAllRejected(t *testing.T) {
	env := Env{
		AWSKeyProber: &fakeProber{},
		CapturedAWSKeys: []secrets.AWSKeyCredential{
			{AccessKeyID: "AKIADEAD000000000001", SecretAccessKey: "s"},
		},
	}
	ev, _ := (&exposedSecretLiveness{}).Validate(context.Background(), env, exposedFinding())
	if ev == nil || ev.Verdict != VerdictUnconfirmed {
		t.Fatalf("all-rejected should be unconfirmed, got %+v", ev)
	}
}

func TestLivenessBlockedWhenAllProbesFail(t *testing.T) {
	env := Env{
		AWSKeyProber: &fakeProber{blocked: map[string]bool{"AKIABLOCK00000000001": true}},
		CapturedAWSKeys: []secrets.AWSKeyCredential{
			{AccessKeyID: "AKIABLOCK00000000001", SecretAccessKey: "s"},
		},
	}
	ev, _ := (&exposedSecretLiveness{}).Validate(context.Background(), env, exposedFinding())
	if ev == nil || ev.Verdict != VerdictBlocked {
		t.Fatalf("all-blocked should be blocked, got %+v", ev)
	}
}

func TestLivenessRegisteredAndSafe(t *testing.T) {
	v := &exposedSecretLiveness{}
	if v.BlastRadius() != BlastRadiusNone {
		t.Error("liveness validator must declare blast radius none")
	}
	if v.CheckID() != "aws_exposed_secret" {
		t.Errorf("unexpected check id %q", v.CheckID())
	}
}
