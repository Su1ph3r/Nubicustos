package validate

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func azureSQLFinding(server string) findings.Finding {
	return findings.Finding{
		CheckID:  "azure_sql_public_network_access",
		Resource: findings.Resource{ID: server, Name: server, Type: "azure_sql_server"},
	}
}

func TestSQLServerFQDN(t *testing.T) {
	cases := map[string]string{
		"mydb":                      "mydb.database.windows.net",
		"mydb.database.windows.net": "mydb.database.windows.net",
		"":                          "",
	}
	for in, want := range cases {
		if got := sqlServerFQDN(in); got != want {
			t.Errorf("sqlServerFQDN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAzureSQLReachableConfirmedAndSkip(t *testing.T) {
	v := &azureSQLPublicReachable{}

	// No server name → nothing to probe.
	if ev, _ := v.Validate(context.Background(), Env{}, azureSQLFinding("")); ev != nil {
		t.Fatalf("empty server name should be skipped (nil evidence), got %+v", ev)
	}

	// A reachable endpoint (injected dial to a live loopback listener) → confirmed.
	addr, cleanup := listenOnce(t, nil) // silent, client-speaks-first server (held open)
	defer cleanup()
	v.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		// Ignore the constructed FQDN:1433 and dial the test listener instead.
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ev, err := v.Validate(ctx, Env{}, azureSQLFinding("prod-sql"))
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("a reachable Azure SQL endpoint should be confirmed, got %+v", ev)
	}
	if ev.Vantage != findings.VantageExternal {
		t.Errorf("Azure SQL reachability is an external-vantage proof, got %s", ev.Vantage)
	}
}
