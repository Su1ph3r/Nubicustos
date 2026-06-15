package web

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/compliance"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/export"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/plugins"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

// handleMeta advertises version + mode + capabilities. The UI renders action
// affordances purely off `capabilities`; the server enforces independently.
func (s *Server) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":                "nubicustos",
		"version":             s.version,
		"schema_version":      "1.0",
		"mode":                string(s.mode),
		"capabilities":        s.capabilities(),
		"providers_supported": []string{"aws", "azure", "gcp", "k8s"},
	})
}

// scanDTO is the wire shape for a scan — snake_case keys and RFC3339 timestamps
// per the API contract, decoupling the response from the store struct.
type scanDTO struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	Account      string `json:"account"`
	Identity     string `json:"identity"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at,omitempty"`
	FindingCount int    `json:"finding_count"`
}

func toScanDTO(m store.ScanMeta) scanDTO {
	d := scanDTO{ID: m.ID, Provider: m.Provider, Account: m.Account, Identity: m.Identity, FindingCount: m.FindingCount}
	if !m.StartedAt.IsZero() {
		d.StartedAt = m.StartedAt.UTC().Format(time.RFC3339)
	}
	if !m.FinishedAt.IsZero() {
		d.FinishedAt = m.FinishedAt.UTC().Format(time.RFC3339)
	}
	return d
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 0)
	scans, err := s.store.ListScans(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	out := make([]scanDTO, 0, len(scans))
	for _, m := range scans {
		out = append(out, toScanDTO(m))
	}
	writeJSON(w, http.StatusOK, list{Data: out, Total: len(out)})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	meta, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toScanDTO(meta))
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	fs, err := s.store.LoadFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	paths, err := s.store.LoadAttackPaths(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	sev := map[findings.Severity]int{}
	reach := map[findings.Reachability]int{}
	for _, f := range fs {
		sev[f.Severity]++
		reach[f.Reachable]++
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].Score > paths[j].Score })
	top := paths
	if len(top) > 5 {
		top = top[:5]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id": id,
		"severity": map[string]int{
			"critical": sev[findings.SeverityCritical], "high": sev[findings.SeverityHigh],
			"medium": sev[findings.SeverityMedium], "low": sev[findings.SeverityLow],
			"info": sev[findings.SeverityInfo],
		},
		"reachability": map[string]int{
			"reachable":     reach[findings.ReachYes],
			"not_reachable": reach[findings.ReachNo],
			"unknown":       reach[findings.ReachUnknown],
		},
		"top_paths": top,
		"total":     len(fs),
	})
}

// handleCompliance maps the scan's findings onto the requested compliance
// framework's controls (soc2|pci|nist, default soc2). The control coverage comes
// from the registered check catalog; the scan's open findings mark pass/fail.
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	framework := strings.ToLower(r.URL.Query().Get("framework"))
	if framework == "" {
		framework = compliance.FrameworkSOC2
	}
	if !compliance.ValidFramework(framework) {
		writeError(w, http.StatusBadRequest, "bad_request", "framework must be soc2 | pci | nist")
		return
	}
	fs, err := s.store.LoadFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	var specs []findings.CheckSpec
	for _, c := range engine.Checks() {
		specs = append(specs, c.Spec())
	}
	writeJSON(w, http.StatusOK, compliance.Build(framework, specs, fs))
}

// handleFindings loads the scan's findings and applies the facet filters, sort,
// and pagination in the handler (findings per scan are bounded). This keeps all
// the facet logic — severity, service, provider, reachability, has-evidence —
// in one place rather than split between SQL and Go.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	fs, err := s.store.LoadFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	q := r.URL.Query()
	sevSet := csvSet(q.Get("severity"))
	svcSet := csvSet(q.Get("service"))
	provSet := csvSet(q.Get("provider"))
	reach := q.Get("reachable") // reachable|not_reachable|unknown|""
	hasEvidence := q.Get("has_evidence") == "true"

	filtered := fs[:0:0]
	for _, f := range fs {
		if len(sevSet) > 0 && !sevSet[string(f.Severity)] {
			continue
		}
		if len(svcSet) > 0 && !svcSet[f.Service] {
			continue
		}
		if len(provSet) > 0 && !provSet[f.Provider] {
			continue
		}
		if reach != "" && !reachMatch(reach, f.Reachable) {
			continue
		}
		if hasEvidence && len(f.Evidence) == 0 {
			continue
		}
		filtered = append(filtered, f)
	}

	sortFindings(filtered, q.Get("sort"))

	total := len(filtered)
	limit := atoiDefault(q.Get("limit"), 0)
	offset := atoiDefault(q.Get("offset"), 0)
	page := paginate(filtered, limit, offset)
	writeJSON(w, http.StatusOK, list{Data: page, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	fid := r.PathValue("fid")
	fs, err := s.store.LoadFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	for _, f := range fs {
		if f.ID == fid {
			writeJSON(w, http.StatusOK, f)
			return
		}
	}
	writeError(w, http.StatusNotFound, "finding_not_found", "no finding "+fid)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	svcs, err := s.store.DistinctServices(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list{Data: svcs, Total: len(svcs)})
}

func (s *Server) handlePaths(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	paths, err := s.store.LoadAttackPaths(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].Score > paths[j].Score })
	writeJSON(w, http.StatusOK, list{Data: paths, Total: len(paths)})
}

func (s *Server) handlePath(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	pid := r.PathValue("pid")
	paths, err := s.store.LoadAttackPaths(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	for _, p := range paths {
		if p.ID == pid {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	writeError(w, http.StatusNotFound, "path_not_found", "no attack path "+pid)
}

// handleExport renders a stored scan in the requested format and streams it as
// a download.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resolveScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	format := r.PathValue("format")
	meta, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan_not_found", err.Error())
		return
	}
	fs, err := s.store.LoadFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	var contentType, filename string
	var render func() error
	now := time.Now().UTC()
	switch format {
	case "cairn":
		contentType, filename = "application/json", id+".cairn.json"
		render = func() error { return export.Cairn(w, meta.Provider, meta.Account, fs, now) }
	case "sarif":
		contentType, filename = "application/json", id+".sarif.json"
		render = func() error { return export.SARIF(w, fs, now) }
	case "csv":
		contentType, filename = "text/csv", id+".csv"
		render = func() error { return export.CSV(w, fs) }
	case "html":
		contentType, filename = "text/html; charset=utf-8", id+".html"
		render = func() error { return export.HTML(w, meta.Provider, meta.Account, fs, now) }
	default:
		writeError(w, http.StatusBadRequest, "bad_format", "format must be cairn|sarif|csv|html")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_ = render() // status already committed; nothing useful to send on a late error
}

func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	history := pluginHistory(r, s.store)
	out := make([]map[string]any, 0, len(plugins.Builtin))
	for _, m := range plugins.Builtin {
		row := map[string]any{
			"name": m.Name, "category": m.Service, "available": plugins.Available(m),
			"has_run": false, "findings": 0, "last_run": "",
		}
		if meta, ok := history[m.Name]; ok {
			row["has_run"] = true
			row["last_run"] = meta.StartedAt.UTC().Format(time.RFC3339)
			row["findings"] = meta.FindingCount
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, list{Data: out, Total: len(out)})
}

// handlePreflight returns the most recent preflight report. It is run on demand
// in operator mode (POST /preflight/run) and held in memory; a read-only
// instance has none, and 404s.
func (s *Server) handlePreflight(w http.ResponseWriter, _ *http.Request) {
	s.pfMu.Lock()
	rep := s.pfReport
	s.pfMu.Unlock()
	if rep == nil {
		writeError(w, http.StatusNotFound, "no_preflight", "no preflight report yet; run one in operator mode")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// --- helpers ---------------------------------------------------------------

func pluginHistory(r *http.Request, st *store.Store) map[string]store.ScanMeta {
	out := map[string]store.ScanMeta{}
	scans, err := st.ListScans(r.Context(), 0)
	if err != nil {
		return out
	}
	for _, sm := range scans { // newest-first; first per tool wins
		name, ok := strings.CutPrefix(sm.Provider, "plugin:")
		if !ok {
			continue
		}
		if _, seen := out[name]; !seen {
			out[name] = sm
		}
	}
	return out
}

func reachMatch(want string, r findings.Reachability) bool {
	switch want {
	case "reachable":
		return r == findings.ReachYes
	case "not_reachable":
		return r == findings.ReachNo
	case "unknown":
		return r == findings.ReachUnknown
	}
	return true
}

// sortFindings orders fs by key ("severity" default, "service", "region"); a
// leading "-" reverses. Severity sorts most-severe-first, tie-broken by id.
func sortFindings(fs []findings.Finding, key string) {
	dir := 1
	if strings.HasPrefix(key, "-") {
		dir, key = -1, key[1:]
	}
	var less func(i, j int) bool
	switch key {
	case "service":
		less = func(i, j int) bool { return fs[i].Service < fs[j].Service }
	case "region":
		less = func(i, j int) bool { return fs[i].Resource.Region < fs[j].Resource.Region }
	default: // severity, most-severe first, then stable by id
		less = func(i, j int) bool {
			if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
				return fs[i].Severity.Rank() > fs[j].Severity.Rank()
			}
			return fs[i].ID < fs[j].ID
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if dir < 0 {
			return less(j, i)
		}
		return less(i, j)
	})
}

func paginate[T any](items []T, limit, offset int) []T {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return items[:0]
	}
	items = items[offset:]
	if limit > 0 && limit < len(items) {
		items = items[:limit]
	}
	return items
}

func csvSet(v string) map[string]bool {
	if v == "" {
		return nil
	}
	out := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
