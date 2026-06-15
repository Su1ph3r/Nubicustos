package preflight

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

func TestAzureDecision(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Decision
	}{
		{"success is allowed", nil, DecisionAllowed},
		{"no resource to probe is unknown", errNoResource, DecisionUnknown},
		{"403 is denied", &azcore.ResponseError{StatusCode: http.StatusForbidden}, DecisionDenied},
		{"AuthorizationFailed code is denied", &azcore.ResponseError{ErrorCode: "AuthorizationFailed"}, DecisionDenied},
		{"a 500 is unknown, not denied", &azcore.ResponseError{StatusCode: 500, ErrorCode: "InternalError"}, DecisionUnknown},
		{"a plain error is unknown", errors.New("dial tcp: timeout"), DecisionUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := azureDecision(c.err); got != c.want {
				t.Errorf("azureDecision(%v) = %s, want %s", c.err, got, c.want)
			}
		})
	}
}

func TestAzureProberMapsActionsThroughReads(t *testing.T) {
	p := &azureProber{reads: map[string]func(ctx context.Context) error{
		"Microsoft.Storage/storageAccounts/read": func(context.Context) error { return nil },
		"Microsoft.KeyVault/vaults/read":         func(context.Context) error { return &azcore.ResponseError{StatusCode: http.StatusForbidden} },
		"Microsoft.Web/sites/config/list/Action": func(context.Context) error { return errNoResource },
	}}
	if got := p.Probe(context.Background(), "Microsoft.Storage/storageAccounts/read"); got != DecisionAllowed {
		t.Errorf("allowed read should be allowed, got %s", got)
	}
	if got := p.Probe(context.Background(), "Microsoft.KeyVault/vaults/read"); got != DecisionDenied {
		t.Errorf("403 read should be denied, got %s", got)
	}
	if got := p.Probe(context.Background(), "Microsoft.Web/sites/config/list/Action"); got != DecisionUnknown {
		t.Errorf("no-resource read should be unknown, got %s", got)
	}
	// An action with no wired read is unknown (not probed).
	if got := p.Probe(context.Background(), "Microsoft.Network/networkSecurityGroups/read"); got != DecisionUnknown {
		t.Errorf("unwired action should be unknown, got %s", got)
	}
}

func TestAzureRemediatorReadyNeedsNoRole(t *testing.T) {
	tr := ToolReport{Readiness: ReadinessReady, Allowed: []string{"a", "b"}}
	rem := NewAzureRemediator("sub-1").Build(AzureTools[0], tr)
	if rem.PolicyDocument != "" {
		t.Errorf("a ready tool needs no custom role, got %q", rem.PolicyDocument)
	}
	if !strings.Contains(rem.Summary, "ready") {
		t.Errorf("summary should say ready: %q", rem.Summary)
	}
}

func TestAzureRemediatorEmitsCustomRoleForMissing(t *testing.T) {
	tr := ToolReport{
		Readiness: ReadinessPartial,
		Allowed:   []string{"Microsoft.Storage/storageAccounts/read"},
		Denied:    []string{"Microsoft.KeyVault/vaults/read"},
	}
	rem := NewAzureRemediator("sub-1").Build(AzureTools[0], tr)
	doc := rem.PolicyDocument
	if !strings.Contains(doc, "Microsoft.KeyVault/vaults/read") {
		t.Errorf("custom role must grant the missing action:\n%s", doc)
	}
	if strings.Contains(doc, "Microsoft.Storage/storageAccounts/read") {
		t.Errorf("custom role must NOT include already-allowed actions:\n%s", doc)
	}
	if !strings.Contains(doc, `"IsCustom": true`) || !strings.Contains(doc, "/subscriptions/sub-1") {
		t.Errorf("document should be an Azure custom role scoped to the subscription:\n%s", doc)
	}
	// The recommended built-in roles surface in the summary.
	if !strings.Contains(rem.Summary, "Reader") || !strings.Contains(rem.Summary, "Website Contributor") {
		t.Errorf("summary should name the built-in roles: %q", rem.Summary)
	}
}

func TestAzureRemediatorNotesUnverified(t *testing.T) {
	tr := ToolReport{Readiness: ReadinessUnverified, Unknown: []string{"Microsoft.Web/sites/config/list/Action"}}
	rem := NewAzureRemediator("sub-1").Build(AzureTools[0], tr)
	if !strings.Contains(rem.Summary, "could not be verified") {
		t.Errorf("summary should flag the unverified permission: %q", rem.Summary)
	}
}

// End-to-end through the generic engine with the Azure remediator.
func TestEvaluateAzureProbeOnly(t *testing.T) {
	// All required Azure actions allowed by the probe → ready, no role emitted.
	allow := map[string]Decision{}
	for _, a := range nubicustosAzureActions {
		allow[a] = DecisionAllowed
	}
	rep := Evaluate(context.Background(), Options{
		Provider:   "azure",
		Account:    "sub-1",
		Tools:      AzureTools,
		Prober:     fakeProbe{d: allow},
		Remediator: NewAzureRemediator("sub-1"),
	})
	if rep.Overall != ReadinessReady {
		t.Fatalf("all-allowed Azure probe should be ready, got %s", rep.Overall)
	}
	if !strings.Contains(rep.Method, "live probe") {
		t.Errorf("Azure method should be live probe, got %q", rep.Method)
	}
	if rep.Tools[0].Remediate.PolicyDocument != "" {
		t.Errorf("ready Azure tool needs no role document")
	}
}

func TestAzureCatalogWellFormed(t *testing.T) {
	if _, ok := AzureToolByKey("nubicustos"); !ok {
		t.Fatal("native Azure tool must be in the catalog")
	}
	if _, ok := AzureToolByKey("nope"); ok {
		t.Error("unknown key must not resolve")
	}
	for _, a := range nubicustosAzureActions {
		if !strings.Contains(a, "/") || !strings.HasPrefix(a, "Microsoft.") {
			t.Errorf("malformed ARM action %q", a)
		}
	}
}
