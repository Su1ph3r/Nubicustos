package azure

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestAzureExposedSecretGroupsBySubscription(t *testing.T) {
	st := state.New()
	st.AddAzureSecretHit(state.SecretHit{
		Detector: "azure_connection_string", Kind: "App Service connection string",
		Surface: "azure_appservice_connstring", Resource: "web-prod", Account: "sub-a",
		Region: "eastus", Locator: "Default", Masked: "****a1b2",
	})
	st.AddAzureSecretHit(state.SecretHit{
		Detector: "generic_secret", Kind: "High-entropy secret", Surface: "azure_appservice_setting",
		Resource: "web-prod", Account: "sub-a", Region: "eastus", Locator: "API_TOKEN", Masked: "****c3d4",
	})
	st.AddAzureSecretHit(state.SecretHit{
		Detector: "aws_access_key_id", Kind: "AWS access key id", Surface: "azure_appservice_setting",
		Resource: "func-dev", Account: "sub-b", Region: "westus", Locator: "AWS_KEY", Masked: "****MPLE",
	})

	got, err := exposedSecret{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected one finding per subscription (2), got %d", len(got))
	}
	// Deterministic: sub-a sorts before sub-b.
	if got[0].Resource.Account != "sub-a" || got[1].Resource.Account != "sub-b" {
		t.Fatalf("findings not ordered by subscription: %s, %s", got[0].Resource.Account, got[1].Resource.Account)
	}
	if len(got[0].Affected) != 2 {
		t.Errorf("sub-a should aggregate 2 hits, got %d", len(got[0].Affected))
	}
	if got[0].Severity != "high" {
		t.Errorf("severity = %q, want high", got[0].Severity)
	}
	for _, f := range got {
		for _, a := range f.Affected {
			if !strings.Contains(a.Detail, "****") {
				t.Errorf("affected detail must carry a masked value: %q", a.Detail)
			}
		}
	}
}

func TestAzureExposedSecretNoHits(t *testing.T) {
	st := state.New()
	got, err := exposedSecret{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected no finding when no secrets detected, got %+v", got)
	}
}
