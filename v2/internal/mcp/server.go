// Package mcp serves the scanner's stored results to an LLM over the Model
// Context Protocol (plan §3.7), replacing the v1 Python MCP service. It is
// strictly read-only: the tools query the local SQLite store (scans, findings,
// attack paths). It deliberately exposes no scan-trigger tool — launching a
// cloud scan with live credentials is not something to hand an MCP client.
package mcp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/Su1ph3r/nubicustos/internal/compliance"
	"github.com/Su1ph3r/nubicustos/internal/diff"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

// NewServer builds the MCP server with read-only tools backed by the store.
func NewServer(st *store.Store, version string) *server.MCPServer {
	s := server.NewMCPServer("nubicustos", version)

	s.AddTool(mcp.NewTool("list_scans",
		mcp.WithDescription("List stored scans (newest first): id, provider, account, finding count, and timestamps.")),
		listScans(st))

	s.AddTool(mcp.NewTool("scan_summary",
		mcp.WithDescription("Severity counts and attack-path count for a scan."),
		mcp.WithString("scan", mcp.Description("Scan id, or \"latest\" (default)."), mcp.DefaultString("latest"))),
		scanSummary(st))

	s.AddTool(mcp.NewTool("list_findings",
		mcp.WithDescription("List findings for a scan, optionally filtered by severity and service."),
		mcp.WithString("scan", mcp.Description("Scan id, or \"latest\" (default)."), mcp.DefaultString("latest")),
		mcp.WithString("severity", mcp.Description("Comma-separated severities to include, e.g. \"critical,high\".")),
		mcp.WithString("service", mcp.Description("Comma-separated services to include, e.g. \"iam,s3\"."))),
		listFindings(st))

	s.AddTool(mcp.NewTool("get_finding",
		mcp.WithDescription("Full detail of one finding (rationale, impact, remediation, PoC, evidence) by its id."),
		mcp.WithString("scan", mcp.Description("Scan id, or \"latest\" (default)."), mcp.DefaultString("latest")),
		mcp.WithString("id", mcp.Description("The finding id."), mcp.Required())),
		getFinding(st))

	s.AddTool(mcp.NewTool("list_attack_paths",
		mcp.WithDescription("List the attack paths for a scan, highest score first, with their chained PoC steps."),
		mcp.WithString("scan", mcp.Description("Scan id, or \"latest\" (default)."), mcp.DefaultString("latest"))),
		listAttackPaths(st))

	s.AddTool(mcp.NewTool("scan_diff",
		mcp.WithDescription("Compare two scans of the same estate and report posture drift: findings added or resolved, exposures that opened (a finding that became internet-reachable), severity shifts, and attack paths gained or lost. Defaults to the latest scan against the one before it."),
		mcp.WithString("to", mcp.Description("Newer scan id, or \"latest\" (default)."), mcp.DefaultString("latest")),
		mcp.WithString("from", mcp.Description("Baseline scan id. Defaults to the scan immediately before \"to\"."))),
		scanDiff(st))

	s.AddTool(mcp.NewTool("compliance_report",
		mcp.WithDescription("Map the native check catalog (and a scan's open findings) onto a compliance framework's controls. Each control lists the checks that assess it and is marked pass/fail by the scan."),
		mcp.WithString("framework", mcp.Description("Framework: soc2 | pci | nist."), mcp.Required()),
		mcp.WithString("scan", mcp.Description("Scan id, or \"latest\" (default)."), mcp.DefaultString("latest"))),
		complianceReport(st))

	return s
}

func scanDiff(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		toID, err := resolveScan(ctx, st, req.GetString("to", "latest"))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("resolving \"to\" scan", err), nil
		}
		fromArg := req.GetString("from", "")
		var fromID string
		if fromArg == "" {
			fromID, err = st.PreviousScanID(ctx, toID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return mcp.NewToolResultError(fmt.Sprintf("scan %s is the earliest scan; need at least two scans to diff (or pass \"from\")", toID)), nil
				}
				return mcp.NewToolResultErrorFromErr("finding baseline scan", err), nil
			}
		} else if fromID, err = resolveScan(ctx, st, fromArg); err != nil {
			return mcp.NewToolResultErrorFromErr("resolving \"from\" scan", err), nil
		}
		if fromID == toID {
			return mcp.NewToolResultError(fmt.Sprintf("\"from\" and \"to\" resolve to the same scan (%s)", toID)), nil
		}

		fromSnap, err := loadDiffSnapshot(ctx, st, fromID)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("loading baseline scan", err), nil
		}
		toSnap, err := loadDiffSnapshot(ctx, st, toID)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("loading current scan", err), nil
		}
		return jsonResult(diff.Compute(fromSnap, toSnap))
	}
}

// loadDiffSnapshot reads a scan's findings and attack paths into a diff.Snapshot.
func loadDiffSnapshot(ctx context.Context, st *store.Store, scanID string) (diff.Snapshot, error) {
	meta, err := st.GetScan(ctx, scanID)
	if err != nil {
		return diff.Snapshot{}, err
	}
	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
	if err != nil {
		return diff.Snapshot{}, err
	}
	paths, err := st.LoadAttackPaths(ctx, scanID)
	if err != nil {
		return diff.Snapshot{}, err
	}
	return diff.Snapshot{ScanID: scanID, StartedAt: meta.StartedAt, Findings: fs, Paths: paths}, nil
}

func complianceReport(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		framework := req.GetString("framework", "")
		if !compliance.ValidFramework(framework) {
			return mcp.NewToolResultError("framework must be soc2 | pci | nist"), nil
		}
		var specs []findings.CheckSpec
		for _, c := range engine.Checks() {
			specs = append(specs, c.Spec())
		}
		// Overlay a scan's findings for pass/fail when a scan exists; otherwise
		// return the pure coverage matrix.
		var fs []findings.Finding
		if scanID, err := resolveScan(ctx, st, req.GetString("scan", "latest")); err == nil {
			fs, _ = st.LoadFindings(ctx, scanID, store.FindingFilter{})
		}
		return jsonResult(compliance.Build(framework, specs, fs))
	}
}

// resolveScan maps a "scan" argument ("" or "latest" → most recent) to a scan id.
func resolveScan(ctx context.Context, st *store.Store, requested string) (string, error) {
	if requested != "" && requested != "latest" {
		if _, err := st.GetScan(ctx, requested); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", fmt.Errorf("scan %q not found", requested)
			}
			return "", err
		}
		return requested, nil
	}
	id, err := st.LatestScanID(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no scans in this database yet")
		}
		return "", err
	}
	return id, nil
}

func listScans(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scans, err := st.ListScans(ctx, 0)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("listing scans", err), nil
		}
		return jsonResult(scans)
	}
}

func scanSummary(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scanID, err := resolveScan(ctx, st, req.GetString("scan", "latest"))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("resolving scan", err), nil
		}
		fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
		if err != nil {
			return mcp.NewToolResultErrorFromErr("loading findings", err), nil
		}
		paths, err := st.CountAttackPaths(ctx, scanID)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("counting attack paths", err), nil
		}
		counts := map[string]int{}
		for _, f := range fs {
			counts[string(f.Severity)]++
		}
		return jsonResult(map[string]any{
			"scan":           scanID,
			"total_findings": len(fs),
			"by_severity":    counts,
			"attack_paths":   paths,
		})
	}
}

func listFindings(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scanID, err := resolveScan(ctx, st, req.GetString("scan", "latest"))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("resolving scan", err), nil
		}
		sevs, err := store.ParseSeverities(req.GetString("severity", ""))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		services := store.SplitCSV(req.GetString("service", ""))
		fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{Severities: sevs, Services: services})
		if err != nil {
			return mcp.NewToolResultErrorFromErr("loading findings", err), nil
		}
		// A requested service that the scan never produced would otherwise return
		// an empty list the LLM could read as "clean". Surface it explicitly so a
		// typo (e.g. "ec2" vs the real service name) cannot masquerade as a result.
		unknown, err := unknownServices(ctx, st, scanID, services)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("verifying service filter", err), nil
		}
		return jsonResult(map[string]any{
			"scan":             scanID,
			"findings":         fs,
			"unknown_services": unknown,
		})
	}
}

// unknownServices returns the requested service names that are not present in
// the scan's findings (nil when no service filter was given).
func unknownServices(ctx context.Context, st *store.Store, scanID string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	present, err := st.DistinctServices(ctx, scanID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(present))
	for _, s := range present {
		set[s] = struct{}{}
	}
	var unknown []string
	for _, want := range requested {
		if _, ok := set[want]; !ok {
			unknown = append(unknown, want)
		}
	}
	return unknown, nil
}

// jsonResult renders v as a tool result, turning a marshal failure into a
// tool-error result (with a nil Go error) so it matches how every other failure
// in this package is reported rather than surfacing as a transport-level error.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	res, err := mcp.NewToolResultJSON(v)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("encoding result", err), nil
	}
	return res, nil
}

func getFinding(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := req.RequireString("id")
		if err != nil {
			return mcp.NewToolResultError("id is required"), nil
		}
		scanID, err := resolveScan(ctx, st, req.GetString("scan", "latest"))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("resolving scan", err), nil
		}
		fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
		if err != nil {
			return mcp.NewToolResultErrorFromErr("loading findings", err), nil
		}
		for _, f := range fs {
			if f.ID == id {
				return jsonResult(f)
			}
		}
		return mcp.NewToolResultError(fmt.Sprintf("no finding %q in scan %s", id, scanID)), nil
	}
}

func listAttackPaths(st *store.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scanID, err := resolveScan(ctx, st, req.GetString("scan", "latest"))
		if err != nil {
			return mcp.NewToolResultErrorFromErr("resolving scan", err), nil
		}
		paths, err := st.LoadAttackPaths(ctx, scanID)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("loading attack paths", err), nil
		}
		return jsonResult(paths)
	}
}
