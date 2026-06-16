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

func TestProbeCapturedKeys(t *testing.T) {
	prober := &fakeProber{
		live:    map[string]string{"AKIALIVE000000000001": "arn:aws:iam::111122223333:role/Builder"},
		blocked: map[string]bool{"AKIABLOCK00000000003": true},
	}
	keys := []secrets.AWSKeyCredential{
		{AccessKeyID: "AKIALIVE000000000001"},
		{AccessKeyID: "AKIADEAD000000000002"},
		{AccessKeyID: "AKIABLOCK00000000003"},
	}
	got, err := ProbeCapturedKeys(context.Background(), keys, prober)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}
	if !got[0].Live || got[0].ARN != "arn:aws:iam::111122223333:role/Builder" {
		t.Errorf("key 0 should be live with its ARN: %+v", got[0])
	}
	if got[1].Live || got[1].Blocked {
		t.Errorf("key 1 should be rejected (not live, not blocked): %+v", got[1])
	}
	if !got[2].Blocked || got[2].Live {
		t.Errorf("key 2 should be blocked: %+v", got[2])
	}
}

func TestProbeCapturedKeysNilProber(t *testing.T) {
	got, err := ProbeCapturedKeys(context.Background(), []secrets.AWSKeyCredential{{AccessKeyID: "x"}}, nil)
	if err != nil || got != nil {
		t.Fatalf("nil prober should yield (nil,nil), got (%v,%v)", got, err)
	}
}

func TestLivenessReusesPreProbedResults(t *testing.T) {
	prober := &fakeProber{live: map[string]string{"AKIALIVE000000000001": "arn:aws:iam::111122223333:user/deploy"}}
	keys := []secrets.AWSKeyCredential{{AccessKeyID: "AKIALIVE000000000001", Surface: "lambda_env", Resource: "fn"}}
	lv, _ := ProbeCapturedKeys(context.Background(), keys, prober)
	probesAfter := len(prober.seen)

	// With pre-probed liveness supplied, the validator must NOT probe again.
	env := Env{CapturedKeyLiveness: lv} // deliberately no prober/keys
	ev, err := (&exposedSecretLiveness{}).Validate(context.Background(), env, exposedFinding())
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("expected confirmed from pre-probed results, got %+v", ev)
	}
	if len(prober.seen) != probesAfter {
		t.Errorf("validator re-probed despite pre-probed liveness (%d extra)", len(prober.seen)-probesAfter)
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
