package azure

import (
	"strings"
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

func TestStorageMinTLSCheck(t *testing.T) {
	st := stateWith(&state.Azure{StorageAccounts: []state.StorageAccount{
		{Name: "old", Subscription: "s1", MinTLSVersion: "TLS1_0"},
		{Name: "ok", Subscription: "s1", MinTLSVersion: "TLS1_2"},
		{Name: "unknown", Subscription: "s1", MinTLSVersion: ""}, // undeterminable → not flagged
	}})
	fs := evalCheck(t, storageMinTLS{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "old" {
		t.Fatalf("only the sub-1.2 account should be flagged, got %+v", fs)
	}
}

func TestStorageSharedKeyAccessCheck(t *testing.T) {
	st := stateWith(&state.Azure{StorageAccounts: []state.StorageAccount{
		{Name: "shared", Subscription: "s1", SharedKeyAccessAllowed: true},
		{Name: "aadonly", Subscription: "s1", SharedKeyAccessAllowed: false},
	}})
	fs := evalCheck(t, storageSharedKeyAccess{}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "shared" {
		t.Fatalf("only the shared-key account should be flagged, got %+v", fs)
	}
}

func TestAppServiceChecks(t *testing.T) {
	st := stateWith(&state.Azure{WebApps: []state.WebApp{
		{Name: "weak", Subscription: "s1", HTTPSOnly: false, MinTLSVersion: "1.0", FtpsState: "AllAllowed"},
	}})
	if fs := evalCheck(t, appServiceNotHTTPSOnly{}, st); len(fs) != 1 {
		t.Fatalf("expected https-only finding, got %d", len(fs))
	}
	if fs := evalCheck(t, appServiceMinTLS{}, st); len(fs) != 1 {
		t.Fatalf("expected min-tls finding, got %d", len(fs))
	}
	if fs := evalCheck(t, appServiceFTPSInsecure{}, st); len(fs) != 1 {
		t.Fatalf("expected ftps finding, got %d", len(fs))
	}
	// A hardened web app produces none.
	hardened := stateWith(&state.Azure{WebApps: []state.WebApp{
		{Name: "good", HTTPSOnly: true, MinTLSVersion: "1.2", FtpsState: "Disabled"},
	}})
	for _, c := range []engine.Check{appServiceNotHTTPSOnly{}, appServiceMinTLS{}, appServiceFTPSInsecure{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened web app should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
	// An undeterminable TLS version (empty config read) is not flagged.
	unknownTLS := stateWith(&state.Azure{WebApps: []state.WebApp{{Name: "x", HTTPSOnly: true, MinTLSVersion: "", FtpsState: ""}}})
	if fs := evalCheck(t, appServiceMinTLS{}, unknownTLS); len(fs) != 0 {
		t.Fatalf("empty min-tls should not be flagged, got %d", len(fs))
	}
}

func TestSQLChecks(t *testing.T) {
	st := stateWith(&state.Azure{SQLServers: []state.SQLServer{
		{Name: "exposed", Subscription: "s1", PublicNetworkAccess: true, MinTLSVersion: "1.0",
			FirewallRules: []state.SQLFirewallRule{
				{Name: "AllowAll", StartIP: "0.0.0.0", EndIP: "255.255.255.255"},
				{Name: "office", StartIP: "203.0.113.0", EndIP: "203.0.113.255"},
			}},
	}})
	if fs := evalCheck(t, sqlPublicNetwork{}, st); len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected one high public-network finding, got %+v", fs)
	}
	if fs := evalCheck(t, sqlFirewallAllowAll{}, st); len(fs) != 1 || !strings.Contains(fs[0].Description, "AllowAll") {
		t.Fatalf("expected the allow-all rule flagged, got %+v", fs)
	}
	if fs := evalCheck(t, sqlMinTLS{}, st); len(fs) != 1 {
		t.Fatalf("expected one min-tls finding, got %d", len(fs))
	}
	// A hardened server (private, scoped firewall, TLS 1.2) produces none.
	hardened := stateWith(&state.Azure{SQLServers: []state.SQLServer{
		{Name: "ok", PublicNetworkAccess: false, MinTLSVersion: "1.2",
			FirewallRules: []state.SQLFirewallRule{{Name: "office", StartIP: "203.0.113.0", EndIP: "203.0.113.255"}}},
	}})
	for _, c := range []engine.Check{sqlPublicNetwork{}, sqlFirewallAllowAll{}, sqlMinTLS{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened SQL server should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
	// The "allow all Azure services" rule (0.0.0.0-0.0.0.0) is not the
	// internet-wide range and must not trip the allow-all check.
	azureSvc := stateWith(&state.Azure{SQLServers: []state.SQLServer{
		{Name: "svc", FirewallRules: []state.SQLFirewallRule{{Name: "AllowAllAzure", StartIP: "0.0.0.0", EndIP: "0.0.0.0"}}},
	}})
	if fs := evalCheck(t, sqlFirewallAllowAll{}, azureSvc); len(fs) != 0 {
		t.Fatalf("the 0.0.0.0-0.0.0.0 Azure-services rule must not be read as internet-wide, got %d", len(fs))
	}
}

func TestNSGOpenIngressSensitivePort(t *testing.T) {
	st := stateWith(&state.Azure{NSGs: []state.NetworkSecurityGroup{
		{Name: "web", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "ssh", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", DestPorts: []string{"22"}, Sources: []string{"Internet"}},
		}},
		{Name: "internal", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "ssh", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", DestPorts: []string{"22"}, Sources: []string{"10.0.0.0/8"}},
		}},
		{Name: "outbound-only", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "x", Direction: "Outbound", Access: "Allow", Protocol: "*", DestPorts: []string{"*"}, Sources: []string{"*"}},
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
			{Name: "all", Direction: "Inbound", Access: "Allow", Protocol: "*", DestPorts: []string{"*"}, Sources: []string{"*"}},
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
			{Name: "r", Direction: "Inbound", Access: "Allow", Protocol: "Tcp", DestPorts: []string{"3380-3400"}, Sources: []string{"Internet"}},
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

func TestNSGInternetSourceNotFirstInList(t *testing.T) {
	// The internet-equivalent source is not the first entry — it must still be found.
	st := stateWith(&state.Azure{NSGs: []state.NetworkSecurityGroup{
		{Name: "multi", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "ssh", Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
				DestPorts: []string{"22"}, Sources: []string{"10.0.0.0/8", "0.0.0.0/0"}},
		}},
	}})
	if fs := evalCheck(t, nsgOpenIngress{}, st); len(fs) != 1 {
		t.Fatalf("internet source later in the list must still be flagged, got %d", len(fs))
	}
}

func TestNSGMultiPortListIncludesSensitive(t *testing.T) {
	// A rule listing several ports must flag every sensitive one, not just the first.
	st := stateWith(&state.Azure{NSGs: []state.NetworkSecurityGroup{
		{Name: "multi", Subscription: "s1", Rules: []state.NSGRule{
			{Name: "many", Direction: "Inbound", Access: "Allow", Protocol: "Tcp",
				DestPorts: []string{"22", "3389", "1433"}, Sources: []string{"Internet"}},
		}},
	}})
	fs := evalCheck(t, nsgOpenIngress{}, st)
	if len(fs) != 1 || !strings.Contains(fs[0].Description, "RDP") || !strings.Contains(fs[0].Description, "MSSQL") {
		t.Fatalf("multi-port rule should flag RDP and MSSQL, got %+v", fs)
	}
}

func TestNSGZeroLengthCIDRIsInternet(t *testing.T) {
	r := state.NSGRule{Direction: "Inbound", Access: "Allow", Sources: []string{"10.0.0.0/0"}}
	if !r.OpenToInternet() {
		t.Fatal("a /0 CIDR in any form is internet-equivalent")
	}
	r2 := state.NSGRule{Direction: "Inbound", Access: "Allow", Sources: []string{"internet"}}
	if !r2.OpenToInternet() {
		t.Fatal("the Internet tag should match case-insensitively")
	}
}

func TestCosmosChecks(t *testing.T) {
	st := stateWith(&state.Azure{CosmosAccounts: []state.CosmosAccount{
		{Name: "c1", Subscription: "s1", PublicNetworkAccess: true, LocalAuthDisabled: false},
	}})
	if fs := evalCheck(t, cosmosPublicNetwork{}, st); len(fs) != 1 || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("expected one high public-network finding, got %+v", fs)
	}
	if fs := evalCheck(t, cosmosLocalAuth{}, st); len(fs) != 1 {
		t.Fatalf("expected local-auth finding, got %d", len(fs))
	}
	hardened := stateWith(&state.Azure{CosmosAccounts: []state.CosmosAccount{
		{Name: "c2", PublicNetworkAccess: false, LocalAuthDisabled: true},
	}})
	for _, c := range []engine.Check{cosmosPublicNetwork{}, cosmosLocalAuth{}} {
		if fs := evalCheck(t, c, hardened); len(fs) != 0 {
			t.Fatalf("%s: hardened account should not be flagged, got %d", c.Spec().ID, len(fs))
		}
	}
}

func TestDefenderPlanFree(t *testing.T) {
	st := stateWith(&state.Azure{DefenderPlans: []state.DefenderPlan{
		{Subscription: "s1", Name: "VirtualMachines", Tier: "Free"},
		{Subscription: "s1", Name: "StorageAccounts", Tier: "Standard"},
		{Subscription: "s1", Name: "SqlServers", Tier: "Free"},
	}})
	fs := evalCheck(t, defenderPlanFree{}, st)
	if len(fs) != 1 { // one aggregate per subscription
		t.Fatalf("expected one aggregate finding for s1, got %d: %+v", len(fs), fs)
	}
	// No free plans → no finding.
	allStd := stateWith(&state.Azure{DefenderPlans: []state.DefenderPlan{{Subscription: "s1", Name: "VirtualMachines", Tier: "Standard"}}})
	if got := evalCheck(t, defenderPlanFree{}, allStd); len(got) != 0 {
		t.Fatalf("all-Standard should yield no finding, got %d", len(got))
	}
}

func TestRBACCustomRoleWildcard(t *testing.T) {
	st := stateWith(&state.Azure{CustomRoles: []state.AzureCustomRole{
		{Name: "superops", Subscription: "s1", WildcardAction: true},
		{Name: "scoped", Subscription: "s1", WildcardAction: false},
	}})
	fs := evalCheck(t, rbacCustomRoleWildcard{}, st)
	if len(fs) != 1 || fs[0].Resource.Name != "superops" || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("only the wildcard custom role should be flagged (high), got %+v", fs)
	}
}

func TestNilAzureStateNoPanic(t *testing.T) {
	st := state.New()
	st.Azure = nil
	for _, c := range []engine.Check{
		storageBlobPublic{}, storageNotHTTPSOnly{}, storageNetworkOpen{}, storageMinTLS{}, storageSharedKeyAccess{},
		nsgOpenIngress{}, kvSoftDelete{}, kvPurgeProtection{}, kvNetworkOpen{},
		appServiceNotHTTPSOnly{}, appServiceMinTLS{}, appServiceFTPSInsecure{},
		sqlPublicNetwork{}, sqlFirewallAllowAll{}, sqlMinTLS{},
		cosmosPublicNetwork{}, cosmosLocalAuth{}, defenderPlanFree{}, rbacCustomRoleWildcard{},
	} {
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
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Sources: []string{"*"}}, true},
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Sources: []string{"Internet"}}, true},
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Sources: []string{"0.0.0.0/0"}}, true},
		{state.NSGRule{Direction: "Inbound", Access: "Deny", Sources: []string{"*"}}, false},
		{state.NSGRule{Direction: "Outbound", Access: "Allow", Sources: []string{"*"}}, false},
		{state.NSGRule{Direction: "Inbound", Access: "Allow", Sources: []string{"10.0.0.0/8"}}, false},
	}
	for i, c := range cases {
		if got := c.rule.OpenToInternet(); got != c.want {
			t.Errorf("case %d: OpenToInternet()=%v want %v", i, got, c.want)
		}
	}
}
