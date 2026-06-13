package web

import (
	"net/http"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/Su1ph3r/nubicustos/internal/preflight"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

// Mode is the server's capability posture.
type Mode string

const (
	ModeReadOnly Mode = "read-only" // default: browse + export only
	ModeOperator Mode = "operator"  // opt-in: live actions (added in later slices)
)

// session is the resolved cloud credential the operator-mode actions use. It is
// set by /auth/login, cleared by /auth/logout, and read by scan/preflight runs.
type session struct {
	cfg       awssdk.Config
	account   string
	identity  string
	method    string
	expiresAt time.Time
	present   bool
}

// Server holds the dependencies and configuration for the web layer.
type Server struct {
	store   *store.Store
	mode    Mode
	version string
	token   string // session token required on /api in operator mode ("" in read-only)
	jobs    *jobManager

	sessMu sync.Mutex
	sess   session

	pfMu     sync.Mutex
	pfReport *preflight.Report // latest preflight report (operator runs; powers GET /preflight)
}

// New builds a server over an open store. mode controls which routes are mounted
// and what /meta advertises; token gates the API in operator mode (ignored in
// read-only mode).
func New(st *store.Store, mode Mode, version, token string) *Server {
	return &Server{store: st, mode: mode, version: version, token: token, jobs: newJobManager()}
}

// Handler returns the full HTTP handler: the read-only REST API under /api/v1
// plus the embedded single-page UI, and — only in operator mode — the action
// routes, with the whole /api surface gated by the session token.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routesRead(mux)
	if s.mode == ModeOperator {
		s.routesOperator(mux)
	}
	mux.Handle("/", s.spaHandler()) // SPA + static assets (catch-all, last)
	if s.mode == ModeOperator {
		return s.tokenGate(mux)
	}
	return mux
}

// capabilities reports the action capabilities for /meta, reflecting what is
// actually mounted (so the UI never offers an action the server won't serve).
func (s *Server) capabilities() []string {
	if s.mode != ModeOperator {
		return []string{}
	}
	return []string{"scan.run", "tools.run", "preflight.run", "auth"}
}

// routesRead registers the always-available read-only API.
func (s *Server) routesRead(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/meta", s.handleMeta)
	mux.HandleFunc("GET /api/v1/scans", s.handleScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/summary", s.handleSummary)
	mux.HandleFunc("GET /api/v1/scans/{id}/findings", s.handleFindings)
	mux.HandleFunc("GET /api/v1/scans/{id}/findings/{fid}", s.handleFinding)
	mux.HandleFunc("GET /api/v1/scans/{id}/services", s.handleServices)
	mux.HandleFunc("GET /api/v1/scans/{id}/paths", s.handlePaths)
	mux.HandleFunc("GET /api/v1/scans/{id}/paths/{pid}", s.handlePath)
	mux.HandleFunc("GET /api/v1/scans/{id}/export/{format}", s.handleExport)
	mux.HandleFunc("GET /api/v1/tools", s.handleTools)
	mux.HandleFunc("GET /api/v1/preflight", s.handlePreflight)
	// Catch-all for the API subtree so an unmatched /api path returns a JSON 404
	// (and, in read-only mode, an operator route reads as absent) rather than
	// falling through to the SPA shell. Specific routes above always win.
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint: "+r.URL.Path)
	})
}

// resolveScan maps the "latest" alias to a concrete scan id, returning ok=false
// (and writing a 404) when the scan does not exist or there are no scans yet.
func (s *Server) resolveScan(w http.ResponseWriter, r *http.Request, id string) (string, bool) {
	if id == "latest" {
		latest, err := s.store.LatestScanID(r.Context())
		if err != nil {
			writeError(w, http.StatusNotFound, "no_scans", "no scans found")
			return "", false
		}
		return latest, true
	}
	if _, err := s.store.GetScan(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "scan_not_found", "no scan "+id)
		return "", false
	}
	return id, true
}
