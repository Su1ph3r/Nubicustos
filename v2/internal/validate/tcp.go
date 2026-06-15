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

func (*rdsPublicReachable) CheckID() string           { return "aws_rds_public" }
func (*rdsPublicReachable) BlastRadius() string       { return BlastRadiusNone }
func (*rdsPublicReachable) Vantage() findings.Vantage { return findings.VantageExternal }

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
			CapturedAt: time.Now().UTC(),
		}
		// A timeout means we could not reach the target at all (filtered path /
		// our network) → blocked. A refusal/reset/no-route is a *single-vantage*
		// negative: the port did not answer from the operator's network, but a
		// security group open to other sources can still make it public. That
		// neither confirms nor refutes the finding, and must not read as
		// "checked-and-clean" — so it is unconfirmed with an explicit note.
		if isTimeout(err) {
			ev.Response = "dial timeout (" + err.Error() + "); could not reach the target from this vantage"
			ev.Verdict = VerdictBlocked
		} else {
			ev.Response = "dial error (" + err.Error() + "); not reachable from this vantage — does not refute config-level public access"
			ev.Verdict = VerdictUnconfirmed
		}
		return ev, nil
	}
	defer conn.Close()

	// The handshake completed. Passively read any banner the server offers,
	// without sending anything, to tell apart a live service from a middlebox.
	deadline := time.Now().Add(bannerReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, maxEvidenceBody)
	n, rerr := conn.Read(buf)

	switch {
	case n > 0:
		// A banner proves a live service answered — reachability confirmed.
		return tcpEvidence(reqDesc, "TCP connection established; banner="+strconv.Quote(printable(buf[:n])), VerdictConfirmed), nil
	case rerr == nil || isTimeout(rerr):
		// The connection stayed open with no banner: a client-speaks-first engine
		// (e.g. PostgreSQL) awaiting the startup packet. Reachability is proven.
		return tcpEvidence(reqDesc, "TCP connection established; no banner within read window (server awaits client)", VerdictConfirmed), nil
	default:
		// The peer accepted the handshake then closed/reset before sending a byte.
		// This can be a real server hanging up, but also a SYN-proxy or scrubbing
		// middlebox that is not the database — so reachability of the service
		// itself is not proven. Do not report this as confirmed.
		return tcpEvidence(reqDesc, "TCP handshake completed but the peer closed/reset before any banner ("+rerr.Error()+"); service reachability inconclusive (possible middlebox)", VerdictUnconfirmed), nil
	}
}

// tcpEvidence builds an external-vantage evidence record for the TCP validator.
func tcpEvidence(req, resp, verdict string) *findings.Evidence {
	return &findings.Evidence{
		Vantage:    findings.VantageExternal,
		Request:    req,
		Response:   resp,
		Verdict:    verdict,
		CapturedAt: time.Now().UTC(),
	}
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
