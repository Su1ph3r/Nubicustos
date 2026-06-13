package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/plugins"
	"github.com/Su1ph3r/nubicustos/internal/preflight"
	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/tui"
)

type tuiFlags struct {
	dbPath string
	scan   string

	// Access preflight (opt-in): resolve a credential before launch so the
	// Tools view can check tool access. Plain browsing needs none of these.
	preflight   bool
	profile     string
	region      string
	mfaSerial   string
	mfaToken    string
	ssoLogin    bool
	nonInteract bool
}

func newTUICmd() *cobra.Command {
	f := &tuiFlags{}
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Browse a scan in the terminal UI",
		Long: "Launch the terminal UI to browse a completed scan: a dashboard, the\n" +
			"findings table with a detail pane, the attack-path list with chained PoCs,\n" +
			"and a Tools view to run optional external scanners. Browsing performs no\n" +
			"cloud calls; running a tool from the Tools view executes that tool locally.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.scan, "scan", "latest", "scan id to browse (or \"latest\")")
	pf.BoolVar(&f.preflight, "preflight", false, "resolve an AWS credential at launch so the Tools view can check tool access")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile (with --preflight)")
	pf.StringVar(&f.region, "region", "", "AWS region for the preflight session")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN (with --preflight)")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` if the SSO session is expired (with --preflight)")
	pf.BoolVar(&f.nonInteract, "non-interactive", false, "never prompt for MFA during --preflight resolution")
	return cmd
}

func runTUI(ctx context.Context, f *tuiFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID, err := resolveScanID(ctx, st, f.scan)
	if err != nil {
		return err
	}
	data, err := loadTUIData(ctx, st, scanID)
	if err != nil {
		return err
	}

	actions := &tuiActions{ctx: ctx, st: st, concurrency: plugins.DefaultSweepConcurrency}

	// Optional: resolve a credential up front (before the alt-screen) so the
	// Tools view can run an access preflight. Done here, not mid-session, so any
	// MFA prompt happens on the normal terminal. A failure is non-fatal —
	// browsing still works, preflight is simply unavailable.
	if f.preflight {
		prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteract)
		cfg, ident, path, aerr := auth.ResolveAWS(ctx, auth.AWSOptions{
			Profile:       f.profile,
			Region:        f.region,
			MFASerial:     f.mfaSerial,
			MFAToken:      f.mfaToken,
			AllowSSOLogin: f.ssoLogin,
		}, prompter)
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "warning: --preflight credential resolution failed (%v); access preflight will be unavailable\n", aerr)
		} else {
			fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)
			actions.pf = &preflightSession{simulator: iam.NewFromConfig(cfg), prober: preflight.NewAWSProber(cfg), identity: ident.ARN, account: ident.Account}
		}
	}

	model := tui.New(data, actions)

	if _, err := tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx)).Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

// loadTUIData assembles the view data for one stored scan.
func loadTUIData(ctx context.Context, st *store.Store, scanID string) (tui.Data, error) {
	meta, err := st.GetScan(ctx, scanID)
	if err != nil {
		return tui.Data{}, err
	}
	fs, err := st.LoadFindings(ctx, scanID, store.FindingFilter{})
	if err != nil {
		return tui.Data{}, err
	}
	paths, err := st.LoadAttackPaths(ctx, scanID)
	if err != nil {
		return tui.Data{}, err
	}
	return tui.Data{
		ScanID:   scanID,
		Provider: meta.Provider,
		Account:  meta.Account,
		Findings: fs,
		Paths:    paths,
	}, nil
}

// preflightSession is the resolved AWS credential context the Tools view uses
// to run an access preflight; nil when the TUI was started without --preflight.
type preflightSession struct {
	simulator preflight.Simulator
	prober    preflight.Prober
	identity  string
	account   string
}

// tuiActions implements tui.Actions over the open store + plugin runner, plus an
// optional preflight session. It binds the command's context so the TUI's run
// commands carry cancellation.
type tuiActions struct {
	ctx         context.Context
	st          *store.Store
	concurrency int
	pf          *preflightSession // nil unless --preflight resolved a credential
}

func (a *tuiActions) ListTools() []tui.ToolStatus {
	history := pluginScanHistory(a.ctx, a.st)
	out := make([]tui.ToolStatus, 0, len(plugins.Builtin))
	for _, m := range plugins.Builtin {
		ts := tui.ToolStatus{Name: m.Name, Category: m.Service, Available: plugins.Available(m)}
		if meta, ok := history[m.Name]; ok {
			ts.HasRun = true
			ts.LastRun = meta.StartedAt.Local().Format("2006-01-02 15:04")
			ts.Findings = meta.FindingCount
		}
		out = append(out, ts)
	}
	return out
}

func (a *tuiActions) RunTool(name, target string) (string, error) {
	if name == "" {
		results := plugins.RunAvailable(a.ctx, target, a.concurrency)
		var ran, skipped, failed, total int
		for _, r := range results {
			switch {
			case !r.Available:
				skipped++
			case r.Err != nil:
				failed++
			default:
				ran++
				total += len(r.Findings)
				if _, err := persistPluginScan(a.ctx, a.st, r.Manifest, target, r.Findings, r.StartedAt, r.FinishedAt); err != nil {
					return "", err
				}
			}
		}
		return fmt.Sprintf("ran %d, skipped %d, failed %d — %d finding(s)", ran, skipped, failed, total), nil
	}

	m, ok := plugins.Lookup(name)
	if !ok {
		return "", fmt.Errorf("unknown tool %q", name)
	}
	started := time.Now().UTC()
	fs, err := plugins.Run(a.ctx, m, target)
	if errors.Is(err, plugins.ErrNotAvailable) {
		return "", fmt.Errorf("%s is not installed", name)
	}
	if err != nil {
		return "", err
	}
	scanID, err := persistPluginScan(a.ctx, a.st, m, target, fs, started, time.Now().UTC())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ran %s — %d finding(s) (scan %s)", name, len(fs), scanID), nil
}

func (a *tuiActions) LatestData() (tui.Data, error) {
	scanID, err := a.st.LatestScanID(a.ctx)
	if err != nil {
		return tui.Data{}, err
	}
	return loadTUIData(a.ctx, a.st, scanID)
}

func (a *tuiActions) PreflightAvailable() bool { return a.pf != nil }

// PreflightTools lists the cloud-access tools as "unchecked" so the Tools view
// can render the group before a preflight is run.
func (a *tuiActions) PreflightTools() []tui.ToolReadiness {
	out := make([]tui.ToolReadiness, 0, len(preflight.AWSTools))
	for _, t := range preflight.AWSTools {
		out = append(out, tui.ToolReadiness{Key: t.Key, Name: t.Name, Readiness: "unchecked"})
	}
	return out
}

func (a *tuiActions) Preflight() ([]tui.ToolReadiness, error) {
	if a.pf == nil {
		return nil, fmt.Errorf("no credential session")
	}
	rep := preflight.Evaluate(a.ctx, preflight.Options{
		Provider:  "aws",
		Identity:  a.pf.identity,
		Account:   a.pf.account,
		Tools:     preflight.AWSTools,
		Simulator: a.pf.simulator,
		Prober:    a.pf.prober,
	})
	out := make([]tui.ToolReadiness, 0, len(rep.Tools))
	for _, t := range rep.Tools {
		out = append(out, tui.ToolReadiness{
			Key:       t.Key,
			Name:      t.Name,
			Readiness: string(t.Readiness),
			Detail:    readinessDetail(t),
		})
	}
	return out, nil
}

// readinessDetail renders a short per-tool summary for the Tools view.
func readinessDetail(t preflight.ToolReport) string {
	switch t.Readiness {
	case preflight.ReadinessReady:
		return fmt.Sprintf("all %d verified", len(t.Allowed))
	case preflight.ReadinessFailed, preflight.ReadinessPartial:
		d := fmt.Sprintf("missing %d of %d", len(t.Denied), len(t.Actions))
		if len(t.Conflicts) > 0 {
			d += fmt.Sprintf(" (%d SCP-blocked)", len(t.Conflicts))
		}
		return d
	case preflight.ReadinessUnverified:
		return fmt.Sprintf("%d/%d verified, %d undetermined", len(t.Allowed), len(t.Actions), len(t.Unknown))
	default:
		return "undetermined"
	}
}
