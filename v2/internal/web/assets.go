package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dist holds the single-page UI (dependency-free vanilla JS/CSS), embedded into
// the binary at compile time — no external assets, no network at runtime.
//
//go:embed all:dist
var dist embed.FS

// spaHandler serves the embedded SPA. Real asset paths are served directly;
// any other non-API path falls back to index.html so client-side routes
// (deep links like /findings) load the app rather than 404.
func (s *Server) spaHandler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Embedding guarantees dist exists; a failure here is a build error.
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusInternalServerError, "ui_unavailable", "embedded UI missing")
		})
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			// Unknown path with no file extension → SPA route; serve the shell.
			// A missing asset (has an extension) gets a real 404 from the server.
			if !strings.Contains(pathBase(p), ".") {
				r.URL.Path = "/"
			}
		}
		files.ServeHTTP(w, r)
	})
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
