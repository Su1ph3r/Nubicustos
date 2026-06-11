package azure

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// stateWith returns a State whose Azure side is set to a.
func stateWith(a *state.Azure) *state.State {
	st := state.New()
	st.Azure = a
	return st
}

func evalCheck(t *testing.T, c engine.Check, st *state.State) []findings.Finding {
	t.Helper()
	fs, err := c.Evaluate(&engine.ScanContext{Provider: "azure"}, st)
	if err != nil {
		t.Fatalf("%s: %v", c.Spec().ID, err)
	}
	return fs
}

func TestStorageBlobPublicFlagged(t *testing.T) {
	st := stateWith(&state.Azure{StorageAccounts: []state.StorageAccount{
		{Name: "open", Subscription: "s1", AllowBlobPublicAccess: true, HTTPSOnly: true},
		{Name: "closed", Subscription: "s1", AllowBlobPublicAccess: false, HTTPSOnly: true},
	}})
	fs := evalCheck(t, storageBlobPublic{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "open" {
		t.Fatalf("expected only the public account flagged, got %+v", fs)
	}
	if fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected high severity, got %s", fs[0].Severity)
	}
}

func TestStorageHTTPSAndNetworkChecks(t *testing.T) {
	st := stateWith(&state.Azure{StorageAccounts: []state.StorageAccount{
		{Name: "a", Subscription: "s1", HTTPSOnly: false, NetworkDefaultAllow: true},
	}})
	if fs := evalCheck(t, storageNotHTTPSOnly{}, st); len(fs) != 1 {
		t.Fatalf("expected https-only finding, got %d", len(fs))
	}
	if fs := evalCheck(t, storageNetworkOpen{}, st); len(fs) != 1 {
		t.Fatalf("expected network-default-allow finding, got %d", len(fs))
	}
	// A locked-down account produces neither.
	clean := stateWith(&state.Azure{StorageAccounts: []state.StorageAccount{
		{Name: "b", HTTPSOnly: true, NetworkDefaultAllow: false},
	}})
	if fs := evalCheck(t, storageNotHTTPSOnly{}, clean); len(fs) != 0 {
		t.Fatalf("clean account should not be flagged, got %d", len(fs))
	}
}

func TestNSGOpenIngressSensitivePort(t *testing.T) {
	st := stateWith(&state.Azure{NSGs: []state.NetworkSecurityGroup{
		{Name: "web", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "ssh", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", DestPorts: "22", Source: "Internet"},
		}},
		{Name: "internal", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "ssh", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", DestPorts: "22", Source: "10.0.0.0/8"},
		}},
		{Name: "outbound-only", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "x", Direction: "Outbound", Access: "Allow", Protocol: "*", DestPorts: "*", Source: "*"},
		}},
	}})
	fs := evalCheck(t, nsgOpenIngress{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "web" {
		t.Fatalf("only the internet-open NSG should be flagged, got %+v", fs)
	}
}

func TestNSGAllPortsWildcardSource(t *testing.T) {
	st := stateWith(&state.Azure{NSGs: []state.NetworkSecurityGroup{
		{Name: "any", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "all", Direction: "Inbound", Access: "Allow", Protocol: "*", DestPorts: "*", Source: "*"},
		}},
	}})
	fs := evalCheck(t, nsgOpenIngress{}, st)
	if len(fs) != 1 {
		t.Fatalf("a wildcard inbound Allow should be flagged, got %d", len(fs))
	}
}

func TestNSGRangeCoversPort(t *testing.T) {
	st := stateWith(&state.Azure{NSGs: []state.NetworkSecurityGroup{
		{Name: "range", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", DestPorts: "3380-3400", Source: "Internet"},
		}},
	}})
	fs := evalCheck(t, nsgOpenIngress{}, st)
	if len(fs) != 1 {
		t.Fatalf("a range covering RDP/3389 should be flagged, got %d", len(fs))
	}
}

func TestKeyVaultChecks(t *testing.T) {
	st := stateWith(&state.Azure{KeyVaults: []state.KeyVault{
		{Name: "v", Subscription: "s1", SoftDeleteEnabled: false, PurgeProtection: false, NetworkDefaultAllow: true},
	}})
	if fs := evalCheck(t, kvSoftDelete{}, st); len(fs) != 1 {
		t.Fatalf("expected soft-delete finding, got %d", len(fs))
	}
	if fs := evalCheck(t, kvPurgeProtection{}, st); len(fs) != 1 {
		t.Fatalf("expected purge-protection finding, got %d", len(fs))
	}
	if fs := evalCheck(t, kvNetworkOpen{}, st); len(fs) != 1 {
		t.Fatalf("expected network-open finding, got %d", len(fs))
	}
	// A hardened vault produces none.
	hardened := stateWith(&state.Azure{KeyVaults: []state.KeyVault{
		{Name: "v2", SoftDeleteEnabled: true, PurgeProtection: true, NetworkDefaultAllow: false},
	}})
	if fs := evalCheck(t, kvSoftDelete{}, hardened); len(fs) != 0 {
		t.Fatalf("hardened vault should not be flagged, got %d", len(fs))
	}
}

func TestNilAzureStateNoPanic(t *testing.T) {
	st := state.New()
	st.Azure = nil
	for _, c := range []engine.Check{storageBlobPublic{}, storageNotHTTPSOnly{}, storageNetworkOpen{}, nsgOpenIngress{}, kvSoftDelete{}, kvPurgeProtection{}, kvNetworkOpen{}} {
		if fs := evalCheck(t, c, st); len(fs) != 0 {
			t.Fatalf("%s on nil azure state should yield nothing, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestOpenToInternetHelper(t *testing.T) {
	cases := []struct {
		rule state.NSGRule
		want bool
	}{
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Source: "*"}, true},
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Source: "Internet"}, true},
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Source: "0.0.0.0/0"}, true},
		{state.NSGRule{Direction: "Inbound", Access: "Deny", Source: "*"}, false},
		{state.NSGRule{Direction: "Outbound", Access: "Allow", Source: "*"}, false},
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Source: "10.0.0.0/8"}, false},
	}
	for i, c := range cases {
		if got := c.rule.OpenToInternet(); got != c.want {
			t.Errorf("case %d: OpenToInternet()=%v want %v", i, got, c.want)
		}
	}
}
