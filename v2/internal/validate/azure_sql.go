package validate

import (
	"context"
	"net"
	"strings"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func init() { Register(&azureSQLPublicReachable{}) }

// azureSQLPublicReachable confirms an "Azure SQL public network access" finding
// by attempting a TCP connection to the server's public endpoint
// (<server>.database.windows.net:1433) from the operator's network vantage. A
// successful connect proves the database is genuinely reachable from outside, not
// merely flagged with public network access enabled while a firewall still blocks
// it. Read-only at the network primitive — connect + passive banner read, never
// a byte sent, no authentication (blast radius none).
type azureSQLPublicReachable struct {
	// dial is injectable for tests; defaults to a context-aware TCP dialer.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (*azureSQLPublicReachable) CheckID() string           { return "azure_sql_public_network_access" }
func (*azureSQLPublicReachable) BlastRadius() string       { return BlastRadiusNone }
func (*azureSQLPublicReachable) Vantage() findings.Vantage { return findings.VantageExternal }

// azureSQLPort is the fixed public TDS endpoint port for Azure SQL Database.
const azureSQLPort = "1433"

func (v *azureSQLPublicReachable) Validate(ctx context.Context, _ Env, f findings.Finding) (*findings.Evidence, error) {
	host := sqlServerFQDN(f.Resource.Name)
	if host == "" {
		return nil, nil // no server name to resolve — nothing to probe
	}
	return probeTCP(ctx, v.dial, net.JoinHostPort(host, azureSQLPort)), nil
}

// sqlServerFQDN builds the public Azure SQL endpoint from a server name. A name
// that already looks fully-qualified is used as-is; an empty name yields "".
func sqlServerFQDN(name string) string {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return ""
	case strings.Contains(name, "."):
		return name // already an FQDN
	default:
		return name + ".database.windows.net"
	}
}
