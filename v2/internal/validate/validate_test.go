package validate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// fakeValidator is a test validator with a controllable verdict and blast radius.
type fakeValidator struct {
	id      string
	blast   string
	vantage findings.Vantage
	ev      *findings.Evidence
	err     error
	calls   int
}

func (f *fakeValidator) CheckID() string           { return f.id }
func (f *fakeValidator) BlastRadius() string       { return f.blast }
func (f *fakeValidator) Vantage() findings.Vantage { return f.vantage }
func (f *fakeValidator) Validate(_ context.Context, _ Env, _ findings.Finding) (*findings.Evidence, error) {
	f.calls++
	return f.ev, f.err
}

// runWith runs a single validator over findings without touching the global
// registry, by constructing the runner state inline. Since Run uses the global
// registry, we register/clean a uniquely-named validator instead.
func registerTemp(t *testing.T, v Validator) {
	t.Helper()
	Register(v)
	t.Cleanup(func() {
		regMu.Lock()
		delete(validators, v.CheckID())
		regMu.Unlock()
	})
}

// noRateLimit returns Options with rate limiting disabled and a fake clock so
// tests never actually sleep.
func noRateLimit() Options {
	return Options{Timeout: time.Second, RateLimit: -1}
}

func TestRunAttachesEvidenceAndCountsConfirmed(t *testing.T) {
	registerTemp(t, &fakeValidator{
		id:    "test_confirm",
		blast: BlastRadiusNone,
		ev:    &findings.Evidence{Verdict: VerdictConfirmed, Vantage: findings.VantageExternal},
	})
	fs := []findings.Finding{{ID: "a", CheckID: "test_confirm"}}
	rep := Run(context.Background(), fs, noRateLimit())

	if rep.Attempted != 1 || rep.Confirmed != 1 {
		t.Fatalf("expected 1 attempted/1 confirmed, got %+v", rep)
	}
	if len(fs[0].Evidence) != 1 || fs[0].Evidence[0].Verdict != VerdictConfirmed {
		t.Fatalf("evidence not attached to finding: %+v", fs[0].Evidence)
	}
}

func TestRunSkipsFindingsWithoutValidator(t *testing.T) {
	fs := []findings.Finding{{ID: "a", CheckID: "no_validator_for_this"}}
	rep := Run(context.Background(), fs, noRateLimit())
	if rep.Attempted != 0 || len(fs[0].Evidence) != 0 {
		t.Fatalf("expected no validation for unhandled check, got %+v", rep)
	}
}

func TestRegisterRejectsUnsafeBlastRadius(t *testing.T) {
	before := registeredCount()
	Register(&fakeValidator{id: "unsafe", blast: "writes-data"})
	if registeredCount() != before {
		regMu.Lock()
		delete(validators, "unsafe")
		regMu.Unlock()
		t.Fatal("a validator not declaring blast radius none must be rejected at registration")
	}
}

func TestRunUnconfirmedDoesNotCount(t *testing.T) {
	registerTemp(t, &fakeValidator{
		id:    "test_unconfirmed",
		blast: BlastRadiusNone,
		ev:    &findings.Evidence{Verdict: VerdictUnconfirmed},
	})
	fs := []findings.Finding{{ID: "a", CheckID: "test_unconfirmed"}}
	rep := Run(context.Background(), fs, noRateLimit())
	if rep.Attempted != 1 || rep.Confirmed != 0 {
		t.Fatalf("unconfirmed must attempt but not confirm, got %+v", rep)
	}
	if len(fs[0].Evidence) != 1 {
		t.Fatal("unconfirmed evidence should still be attached")
	}
}

func TestRunRecordsValidatorErrors(t *testing.T) {
	registerTemp(t, &fakeValidator{id: "test_err", blast: BlastRadiusNone, err: errors.New("boom")})
	fs := []findings.Finding{{ID: "a", CheckID: "test_err"}}
	rep := Run(context.Background(), fs, noRateLimit())
	if rep.Attempted != 1 || len(rep.Errors) != 1 {
		t.Fatalf("expected the validator error recorded, got %+v", rep)
	}
	if len(fs[0].Evidence) != 0 {
		t.Fatal("a failed validation must not attach evidence")
	}
}

func TestRunHonorsCancelledContext(t *testing.T) {
	v := &fakeValidator{id: "test_cancel", blast: BlastRadiusNone, ev: &findings.Evidence{Verdict: VerdictConfirmed}}
	registerTemp(t, v)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before running
	fs := []findings.Finding{{ID: "a", CheckID: "test_cancel"}}
	rep := Run(ctx, fs, noRateLimit())
	if v.calls != 0 {
		t.Fatal("a cancelled context must short-circuit before invoking a validator")
	}
	if len(rep.Errors) == 0 {
		t.Fatal("cancellation should be recorded as an error")
	}
}

func TestRunIsOptInRequiresRegisteredAndMatching(t *testing.T) {
	// The default registry contains the real s3 validator; a finding with a
	// different check id must not trigger any network activity (no validator).
	fs := []findings.Finding{{ID: "a", CheckID: "aws_iam_root_mfa_disabled"}}
	rep := Run(context.Background(), fs, noRateLimit())
	if rep.Attempted != 0 {
		t.Fatalf("only matching findings should be validated, got %+v", rep)
	}
}

func TestAuthenticatedFindingCount(t *testing.T) {
	fs := []findings.Finding{
		{ID: "1", CheckID: "aws_s3_public_access"},      // external
		{ID: "2", CheckID: "aws_rds_public"},            // external
		{ID: "3", CheckID: "aws_ebs_snapshot_public"},   // authenticated
		{ID: "4", CheckID: "aws_ami_public"},            // authenticated
		{ID: "5", CheckID: "aws_rds_snapshot_public"},   // authenticated
		{ID: "6", CheckID: "aws_iam_root_mfa_disabled"}, // no validator
	}
	if got := AuthenticatedFindingCount(fs); got != 3 {
		t.Fatalf("expected 3 authenticated-vantage findings, got %d", got)
	}
	// An external-only set must report zero, so validate never resolves creds.
	ext := []findings.Finding{{ID: "1", CheckID: "aws_s3_public_access"}, {ID: "2", CheckID: "aws_rds_public"}}
	if got := AuthenticatedFindingCount(ext); got != 0 {
		t.Fatalf("external-only set should need no session, got %d", got)
	}
}

func TestRegisteredValidatorsDeclareAKnownVantage(t *testing.T) {
	// Every registered validator must declare a real vantage so the CLI's
	// authenticate-or-not decision is well defined.
	regMu.Lock()
	defer regMu.Unlock()
	for id, v := range validators {
		switch v.Vantage() {
		case findings.VantageExternal, findings.VantageAuthenticated:
		default:
			t.Fatalf("validator %q declares an unknown vantage %q", id, v.Vantage())
		}
	}
}
