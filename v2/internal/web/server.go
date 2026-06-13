package web

import (
	"net/http"

	"github.com/Su1ph3r/nubicustos/internal/store"
)

// Mode is the server's capability posture.
type Mode string

const (
	ModeReadOnly Mode = "read-only" // default: browse + export only
	ModeOperator Mode = "operator"  // opt-in: live actions (added in later slices)
)

// Server holds the dependencies and configuration for the web layer.
type Server struct {
	store   *store.Store
	mode    Mode
	version string
}

// New builds a server over an open store. mode controls which routes are
// mounted and what /meta advertises.
func New(st *store.Store, mode Mode, version string) *Server {
	return &Server{store: st, mode: mode, version: version}
}

// Handler returns the full HTTP handler: the read-only REST API under
// /api/v1 plus the embedded single-page UI. Operator routes are mounted only
// when the server is in operator mode (added in a later slice).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routesRead(mux)
	mux.Handle("/", s.spaHandler()) // SPA + static assets (catch-all, last)
	return mux
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
