package validate

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func rdsFinding(endpoint string) findings.Finding {
	return findings.Finding{
		CheckID:  "aws_rds_public",
		Resource: findings.Resource{ID: "db-1", Type: "aws_db_instance", Endpoint: endpoint},
	}
}

// listenOnce starts a loopback TCP listener that accepts a single connection,
// optionally writes banner to it, then closes. It returns the dial address and
// a cleanup func. It models a reachable database port.
func listenOnce(t *testing.T, banner []byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if len(banner) > 0 {
			_, _ = conn.Write(banner)
		}
		// Hold briefly so the client reads before we close.
		time.Sleep(50 * time.Millisecond)
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestRDSReachableConfirmedWithBanner(t *testing.T) {
	addr, cleanup := listenOnce(t, []byte("5.7.40-MySQL\x00handshake"))
	defer cleanup()

	v := &rdsPublicReachable{}
	ev, err := v.Validate(context.Background(), rdsFinding(addr))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("an open port should confirm, got %+v", ev)
	}
	if ev.Vantage != findings.VantageExternal {
		t.Fatalf("expected external vantage, got %s", ev.Vantage)
	}
	if !strings.Contains(ev.Response, "5.7.40-MySQL") {
		t.Fatalf("banner should be captured: %q", ev.Response)
	}
	// The NUL byte must be sanitized to '.', never embedded raw.
	if strings.ContainsRune(ev.Response, 0x00) {
		t.Fatalf("raw control byte leaked into evidence: %q", ev.Response)
	}
	if !strings.Contains(ev.Request, "no data sent") {
		t.Fatalf("request description should assert no data was sent: %q", ev.Request)
	}
}

func TestRDSReachableConfirmedNoBanner(t *testing.T) {
	addr, cleanup := listenOnce(t, nil) // silent server (client-speaks-first engine)
	defer cleanup()

	v := &rdsPublicReachable{}
	ev, err := v.Validate(context.Background(), rdsFinding(addr))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictConfirmed {
		t.Fatalf("open port with no banner should still confirm, got %+v", ev)
	}
	if !strings.Contains(ev.Response, "no banner") {
		t.Fatalf("expected a no-banner note: %q", ev.Response)
	}
}

func TestRDSReachableUnconfirmedOnRefused(t *testing.T) {
	v := &rdsPublicReachable{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connect: connection refused")
	}}
	ev, err := v.Validate(context.Background(), rdsFinding("db.example.com:5432"))
	if err != nil {
		t.Fatalf("dial error must be captured as evidence, not returned: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictUnconfirmed {
		t.Fatalf("a refused connection should be unconfirmed, got %+v", ev)
	}
}

// timeoutErr is a net.Error reporting a timeout, for the blocked branch.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestRDSReachableBlockedOnTimeout(t *testing.T) {
	v := &rdsPublicReachable{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, timeoutErr{}
	}}
	ev, err := v.Validate(context.Background(), rdsFinding("db.example.com:5432"))
	if err != nil {
		t.Fatalf("timeout must be captured as evidence: %v", err)
	}
	if ev == nil || ev.Verdict != VerdictBlocked {
		t.Fatalf("a timeout (could not determine) should be blocked, got %+v", ev)
	}
}

func TestRDSReachableContextDeadlineBlocked(t *testing.T) {
	v := &rdsPublicReachable{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}}
	ev, _ := v.Validate(context.Background(), rdsFinding("db.example.com:5432"))
	if ev == nil || ev.Verdict != VerdictBlocked {
		t.Fatalf("context deadline should be blocked, got %+v", ev)
	}
}

func TestRDSReachableNoEndpointNoOp(t *testing.T) {
	v := &rdsPublicReachable{}
	ev, err := v.Validate(context.Background(), rdsFinding(""))
	if err != nil || ev != nil {
		t.Fatalf("a finding without an endpoint should be a no-op, got ev=%+v err=%v", ev, err)
	}
}

func TestRDSReachableMalformedEndpointNoOp(t *testing.T) {
	v := &rdsPublicReachable{dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial must not be attempted for a malformed endpoint")
		return nil, nil
	}}
	ev, err := v.Validate(context.Background(), rdsFinding("no-port-here"))
	if err != nil || ev != nil {
		t.Fatalf("a host without a port should be a no-op, got ev=%+v err=%v", ev, err)
	}
}

func TestRDSReachableContractMetadata(t *testing.T) {
	v := &rdsPublicReachable{}
	if v.CheckID() != "aws_rds_public" {
		t.Fatalf("unexpected check id %q", v.CheckID())
	}
	if v.BlastRadius() != BlastRadiusNone {
		t.Fatalf("tcp validator must declare blast radius none, got %q", v.BlastRadius())
	}
}
