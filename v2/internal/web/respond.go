// Package web is the optional embedded HTTP layer: a read-only REST API over
// the results database plus the single-page UI, served by the binary itself.
// It is local-first and same-origin; operator-mode actions (scan/tool runs,
// preflight, auth) are added on top of this read-only foundation behind an
// explicit launch flag.
package web

import (
	"encoding/json"
	"net/http"
)

// list is the envelope for a paginated collection response.
type list struct {
	Data   any `json:"data"`
	Total  int `json:"total"`
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// apiError is the error envelope: { "error": { code, message, detail? } }.
type apiError struct {
	Error errBody `json:"error"`
}
type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// Encode after WriteHeader; on a late encode error there's nothing useful to
	// send, and the status is already committed.
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: errBody{Code: code, Message: message}})
}
