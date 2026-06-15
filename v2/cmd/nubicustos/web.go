package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/web"
)

type webFlags struct {
	dbPath       string
	addr         string
	allowActions bool
}

func newWebCmd() *cobra.Command {
	f := &webFlags{}
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the read-only results UI and REST API over the local database",
		Long: "Serve the embedded single-page UI and a REST API over a stored scan\n" +
			"database. By default it is read-only (browse and export; no cloud calls, no\n" +
			"spawned work) and needs no token. With --allow-actions it enters operator\n" +
			"mode: live actions (currently the external-tool sweep) are enabled, the whole\n" +
			"API is gated by a one-time session token printed at startup, and you should\n" +
			"keep it bound to a loopback address. This is a local tool, not a public\n" +
			"service.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWeb(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.addr, "addr", "127.0.0.1:8088", "address to listen on (use a loopback address)")
	pf.BoolVar(&f.allowActions, "allow-actions", false, "operator mode: enable live actions, gated by a session token")
	return cmd
}

func runWeb(ctx context.Context, f *webFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	mode, token := web.ModeReadOnly, ""
	if f.allowActions {
		mode, token = web.ModeOperator, newSessionToken()
	}
	srv := web.New(st, mode, version, token)
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", f.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", f.addr, err)
	}
	if f.allowActions {
		if !isLoopback(ln.Addr()) {
			fmt.Fprintf(os.Stderr, "warning: operator mode is bound to a non-loopback address (%s) — live actions are reachable off-host\n", ln.Addr())
		}
		fmt.Fprintf(os.Stderr, "nubicustos web (OPERATOR) serving %s\n  open: http://%s/?t=%s\n", f.dbPath, ln.Addr(), token)
	} else {
		fmt.Fprintf(os.Stderr, "nubicustos web (read-only) serving %s on http://%s\n", f.dbPath, ln.Addr())
	}

	// Shut down gracefully when the command context is cancelled (e.g. Ctrl-C).
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newSessionToken returns a 128-bit random hex token for the operator session.
func newSessionToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// isLoopback reports whether addr is a loopback TCP address.
func isLoopback(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
