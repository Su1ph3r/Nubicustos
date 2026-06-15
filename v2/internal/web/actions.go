package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/preflight"
	"github.com/Su1ph3r/nubicustos/internal/progress"
	awsprovider "github.com/Su1ph3r/nubicustos/internal/providers/aws"
	"github.com/Su1ph3r/nubicustos/internal/validate"
)

// --- auth / session --------------------------------------------------------

func (s *Server) currentSession() session {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.sess
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, _ *http.Request) {
	sess := s.currentSession()
	if !sess.present {
		writeJSON(w, http.StatusOK, map[string]any{"status": "none"})
		return
	}
	status := "active"
	if !sess.expiresAt.IsZero() && time.Now().After(sess.expiresAt) {
		status = "expired"
	}
	out := map[string]any{
		"status": status, "provider": "aws",
		"account": sess.account, "identity": sess.identity, "method": sess.method,
	}
	switch {
	case !sess.expiresAt.IsZero():
		out["expires_at"] = sess.expiresAt.UTC().Format(time.RFC3339)
	case !sess.expiryKnown:
		// Expiry could not be determined — say so rather than implying a
		// non-expiring session (which could read as active right up to a failure).
		out["expiry"] = "unknown"
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAuthLogin resolves an AWS credential non-interactively (an MFA TOTP may
// be supplied in the body; SSO is honored only via a valid cached token — this
// runs in an HTTP handler, so it never shells out to a blocking browser login).
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider  string `json:"provider"`
		Profile   string `json:"profile"`
		Region    string `json:"region"`
		MFASerial string `json:"mfa_serial"`
		MFAToken  string `json:"mfa_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.Provider != "" && strings.ToLower(req.Provider) != "aws" {
		writeError(w, http.StatusBadRequest, "unsupported_provider", "web login currently supports aws")
		return
	}

	prompter := auth.NewCLIPrompter(req.MFAToken, false) // non-interactive: no stdin/browser in a handler
	cfg, ident, path, err := auth.ResolveAWS(r.Context(), auth.AWSOptions{
		Profile:   req.Profile,
		Region:    req.Region,
		MFASerial: req.MFASerial,
		MFAToken:  req.MFAToken,
		// AllowSSOLogin deliberately false: an expired SSO session needs an
		// out-of-band `aws sso login`, not a browser launched from this handler.
	}, prompter)
	if err != nil {
		writeError(w, http.StatusBadGateway, "auth_failed", err.Error())
		return
	}

	sess := session{cfg: cfg, account: ident.Account, identity: ident.ARN, method: string(path), present: true}
	if creds, cerr := cfg.Credentials.Retrieve(r.Context()); cerr == nil {
		sess.expiryKnown = true // retrieval succeeded; CanExpire tells us if it has an expiry
		if creds.CanExpire {
			sess.expiresAt = creds.Expires
		}
	}
	s.sessMu.Lock()
	s.sess = sess
	s.sessMu.Unlock()

	s.handleAuthStatus(w, r)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, _ *http.Request) {
	s.sessMu.Lock()
	s.sess = session{}
	s.sessMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// --- scan run --------------------------------------------------------------

func (s *Server) handleScanRun(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession()
	if !sess.present {
		writeError(w, http.StatusConflict, "no_session", "authenticate first (POST /api/v1/auth/login)")
		return
	}
	var req struct {
		Regions  []string `json:"regions"`
		Validate bool     `json:"validate"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	j := s.jobs.create("scan", cancel)
	go j.guard(func() { s.runScanJob(ctx, j, sess, req.Regions, req.Validate) })
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.id, "kind": "scan", "status": jobRunning})
}

func (s *Server) runScanJob(ctx context.Context, j *job, sess session, regions []string, doValidate bool) {
	started := time.Now().UTC()
	reporter := progress.Func(j.emitPhase)
	sc := &engine.ScanContext{
		Ctx: ctx, Provider: "aws", Account: sess.account, AWS: sess.cfg,
		Regions: regions, Progress: reporter,
	}
	if len(sc.Regions) == 0 {
		progress.ReportPhase(reporter, progress.PhaseDiscover, "regions")
		if regs, err := awsprovider.EnabledRegions(ctx, sess.cfg); err == nil && len(regs) > 0 {
			sc.Regions = regs
		} else {
			sc.Regions = []string{sess.cfg.Region}
		}
	}

	result := engine.Run(sc)

	if doValidate {
		progress.ReportPhase(reporter, progress.PhaseValidate, "")
		validate.Run(ctx, result.Findings, validate.Options{Env: validate.NewAWSEnv(sess.cfg)})
	}

	if ctx.Err() != nil {
		j.finishError(jobCancelled, "cancelled")
		return
	}

	progress.ReportPhase(reporter, progress.PhasePersist, "")
	finished := time.Now().UTC()
	id := newScanID()
	if err := s.store.CreateScan(ctx, id, "aws", sess.account, sess.identity, started); err != nil {
		j.finishError(jobError, "persisting scan: "+err.Error())
		return
	}
	// If findings/graph fail to persist, delete the scan row so a half-written
	// scan can never be listed as a complete (empty) one.
	if err := s.store.SaveFindings(ctx, id, result.Findings, finished); err != nil {
		s.cleanupScan(id)
		j.finishError(jobError, "persisting findings: "+err.Error())
		return
	}
	if err := s.store.SaveGraph(ctx, id, result.Graph); err != nil {
		s.cleanupScan(id)
		j.finishError(jobError, "persisting graph: "+err.Error())
		return
	}
	j.emitLog(formatScanSummary(result))
	j.finishDone([]string{id}, formatScanSummary(result))
}

func formatScanSummary(r *engine.Result) string {
	return fmt.Sprintf("scan complete: %d finding(s)", len(r.Findings))
}

// cleanupScan removes a partially-persisted scan row. It uses a fresh context so
// it runs even when the scan's own context was cancelled.
func (s *Server) cleanupScan(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.store.DeleteScan(ctx, id)
}

// --- preflight run ---------------------------------------------------------

func (s *Server) handlePreflightRun(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession()
	if !sess.present {
		writeError(w, http.StatusConflict, "no_session", "authenticate first (POST /api/v1/auth/login)")
		return
	}
	var req struct {
		Tools []string `json:"tools"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	tools, err := selectPreflightTools(req.Tools)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown_tool", err.Error())
		return
	}

	rep := preflight.Evaluate(r.Context(), preflight.Options{
		Provider: "aws", Identity: sess.identity, Account: sess.account,
		Tools:     tools,
		Simulator: iam.NewFromConfig(sess.cfg),
		Prober:    preflight.NewAWSProber(sess.cfg),
	})
	s.pfMu.Lock()
	s.pfReport = &rep
	s.pfMu.Unlock()

	writeJSON(w, http.StatusOK, rep)
}

func selectPreflightTools(keys []string) ([]preflight.Tool, error) {
	if len(keys) == 0 {
		return preflight.AWSTools, nil
	}
	var out []preflight.Tool
	for _, k := range keys {
		t, ok := preflight.AWSToolByKey(strings.TrimSpace(k))
		if !ok {
			return nil, fmt.Errorf("unknown tool %q", k)
		}
		out = append(out, t)
	}
	return out, nil
}
