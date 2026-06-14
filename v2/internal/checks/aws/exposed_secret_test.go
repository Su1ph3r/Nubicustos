package aws

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestExposedSecretAggregatesHits(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("111122223333")
	st.AddSecretHit(state.SecretHit{
		Detector: "aws_access_key_id", Kind: "AWS access key id", Surface: "lambda_env",
		Resource: "ingest-fn", Region: "us-east-1", Locator: "AWS_KEY", Masked: "****MPLE", LastFour: "MPLE",
	})
	st.AddSecretHit(state.SecretHit{
		Detector: "generic_secret", Kind: "High-entropy secret", Surface: "ssm_parameter",
		Resource: "/prod/db/password", Region: "eu-west-1", Locator: "/prod/db/password", Masked: "****a1b2",
	})

	got, err := exposedSecret{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one aggregate finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if len(f.Affected) != 2 {
		t.Fatalf("expected 2 affected items, got %d", len(f.Affected))
	}
	// Deterministic order: eu-west-1 sorts before us-east-1.
	if f.Affected[0].Region != "eu-west-1" {
		t.Errorf("affected not sorted by region: %+v", f.Affected)
	}
	// The finding must never carry a raw secret — only masked renderings.
	for _, a := range f.Affected {
		if !strings.Contains(a.Detail, "****") {
			t.Errorf("affected detail missing masked marker: %q", a.Detail)
		}
	}
}

func TestExposedSecretNoHits(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("111122223333")
	got, err := exposedSecret{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected no finding when no secrets detected, got %+v", got)
	}
}
