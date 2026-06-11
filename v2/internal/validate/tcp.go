package validate

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func init() { Register(&rdsPublicReachable{}) }

// rdsPublicReachable confirms a "publicly accessible" RDS finding by attempting
// a TCP connection to the instance's endpoint from the operator's network
// vantage. A successful connect proves the database port is genuinely reachable
// from outside (the finding's claim), not merely flagged PubliclyAccessible
// while a security group still blocks it.
//
// It is strictly read-only at the network primitive: it connects and passively
// reads whatever the server volunteers (server-speaks-first engines such as
// MySQL send a handshake greeting; Postgres/others stay silent until the client
// speaks). It never sends a byte, never attempts authentication, and never
// writes — blast radius none. Stopping at "the port answers" is the proven
// primitive; we do not log in or run a query.
type rdsPublicReachable struct {
	// dial is injectable for tests; defaults to a context-aware TCP dialer.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (*rdsPublicReachable) CheckID() string     { return "aws_rds_public" }
func (*rdsPublicReachable) BlastRadius() string { return BlastRadiusNone }

// bannerReadTimeout bounds the passive banner read so silent (client-speaks-
// first) engines don't hold the action for the full per-action timeout once the
// connection is already proven open.
const bannerReadTimeout = 750 * time.Millisecond

func (v *rdsPublicReachable) Validate(ctx context.Context, _ Env, f findings.Finding) (*findings.Evidence, error) {
	addr := f.Resource.Endpoint
	if addr == "" {
		return nil, nil // no endpoint collected — nothing to probe
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, nil // not a dial-ready host:port; skip rather than guess
	}

	dial := v.dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	reqDesc := "TCP connect " + addr + "  (no data sent, passive banner read only)"

	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		ev := &findings.Evidence{
			Vantage:    findings.VantageExternal,
			Request:    reqDesc,
			Response:   "dial error: " + err.Error(),
			CapturedAt: time.Now().UTC(),
		}
		// A timeout means we could not determine reachability (filtered path /
		// our network) → blocked. A refusal/reset/no-route means we reached the
		// network but the service port did not answer → the external reachability
		// the finding claims is not confirmed (but config may still be public).
		if isTimeout(err) {
			ev.Verdict = VerdictBlocked
		} else {
			ev.Verdict = VerdictUnconfirmed
		}
		return ev, nil
	}
	defer conn.Close()

	// The connection is open — the port is reachable. Passively read any banner
	// the server offers, without sending anything.
	deadline := time.Now().Add(bannerReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, maxEvidenceBody)
	n, _ := conn.Read(buf)

	resp := "TCP connection established"
	if n > 0 {
		resp += "; banner=" + strconv.Quote(printable(buf[:n]))
	} else {
		resp += "; no banner (server awaits client)"
	}
	return &findings.Evidence{
		Vantage:    findings.VantageExternal,
		Request:    reqDesc,
		Response:   resp,
		Verdict:    VerdictConfirmed,
		CapturedAt: time.Now().UTC(),
	}, nil
}

// isTimeout reports whether err is a network/context timeout.
func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// printable renders captured bytes as a short, safe string: printable ASCII is
// kept; everything else becomes '.', so a binary handshake never corrupts the
// evidence or smuggles control sequences into a terminal.
func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
