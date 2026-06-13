package main

import (
	"context"
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
	dbPath string
	addr   string
}

func newWebCmd() *cobra.Command {
	f := &webFlags{}
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the read-only results UI and REST API over the local database",
		Long: "Serve the embedded single-page UI and a read-only REST API over a stored\n" +
			"scan database. Browse-and-export only; it performs no cloud calls and spawns\n" +
			"no work. Bind to a loopback address; this is a local viewer, not a public\n" +
			"service. (Operator-mode live actions are added behind an explicit flag in a\n" +
			"later release.)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWeb(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.addr, "addr", "127.0.0.1:8088", "address to listen on (use a loopback address)")
	return cmd
}

func runWeb(ctx context.Context, f *webFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := web.New(st, web.ModeReadOnly, version)
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", f.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", f.addr, err)
	}
	fmt.Fprintf(os.Stderr, "nubicustos web (read-only) serving %s on http://%s\n", f.dbPath, ln.Addr())

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
