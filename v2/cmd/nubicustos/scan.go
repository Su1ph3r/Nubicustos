package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/chain"
	ruleschecks "github.com/Su1ph3r/nubicustos/internal/checks/rules"
	"github.com/Su1ph3r/nubicustos/internal/discovery"
	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/export"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/progress"
	awsprovider "github.com/Su1ph3r/nubicustos/internal/providers/aws"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/store"
	"github.com/Su1ph3r/nubicustos/internal/validate"
)

type scanFlags struct {
	provider       string
	profile        string
	regions        []string
	mfaSerial      string
	mfaToken       string
	ssoLogin       bool
	sessionDur     time.Duration
	nonInteractive bool

	// Azure
	authMethod    string
	tenantID      string
	clientID      string
	clientSecret  string
	subscriptions []string

	// GCP
	projects []string

	// Kubernetes
	contexts []string

	// AWS org-wide scanning (§9.4)
	org             bool
	accounts        []string
	excludeAccts    []string
	ous             []string
	orgRole         string
	includeMgmt     bool
	acctConcurrency int

	// Azure estate scoping (§9.4)
	managementGroup string

	dbPath           string
	exportPath       string
	exportContainers string
	validate         bool
	captureSecrets   bool
	rulesDir         string
}

func newScanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a cloud account for misconfigurations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.provider, "provider", "", "cloud provider: aws | azure | gcp | k8s (required)")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile")
	pf.StringSliceVar(&f.regions, "region", nil, "region(s) to scan (repeatable)")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN (for static-keys + MFA-condition profiles)")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` automatically if the SSO session is expired")
	pf.DurationVar(&f.sessionDur, "session-duration", 0, "temp-credential lifetime (e.g. 8h); default 12h")
	pf.BoolVar(&f.nonInteractive, "non-interactive", false, "never prompt; fail fast if MFA input is required")

	pf.StringVar(&f.authMethod, "auth", "", "Azure auth: auto | cli | interactive-browser | device-code | service-principal | managed-identity")
	pf.StringVar(&f.tenantID, "tenant", "", "Azure tenant id (service-principal)")
	pf.StringVar(&f.clientID, "client-id", "", "Azure client id (service-principal)")
	pf.StringVar(&f.clientSecret, "client-secret", "", "Azure client secret (service-principal)")
	pf.StringSliceVar(&f.subscriptions, "subscription", nil, "Azure subscription id(s) to scan (repeatable; default: all enabled)")
	pf.StringSliceVar(&f.projects, "project", nil, "GCP project id(s) to scan (repeatable; default: all active)")
	pf.StringSliceVar(&f.contexts, "context", nil, "Kubernetes context(s) to scan (repeatable; default: current context)")

	pf.BoolVar(&f.org, "org", false, "estate mode: AWS enumerate the organization and scan every member account; K8s scan every kubeconfig context")
	pf.StringSliceVar(&f.accounts, "accounts", nil, "AWS: explicit member account id(s) to scan (implies org mode; skips org enumeration)")
	pf.StringSliceVar(&f.excludeAccts, "exclude", nil, "account/subscription id(s) to skip (AWS org members or Azure subscriptions)")
	pf.StringSliceVar(&f.ous, "ou", nil, "AWS org: restrict to accounts under these OU id(s), recursively (implies org mode)")
	pf.StringVar(&f.orgRole, "org-role", "", "AWS org: role assumed in each member account (default OrganizationAccountAccessRole)")
	pf.BoolVar(&f.includeMgmt, "include-mgmt", false, "AWS org: also scan the management/base account itself")
	pf.IntVar(&f.acctConcurrency, "account-concurrency", 4, "AWS org: how many accounts to scan in parallel")

	pf.StringVar(&f.managementGroup, "management-group", "", "Azure: restrict the scan to subscriptions under this management group (recursive)")

	pf.StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	pf.StringVar(&f.exportPath, "export", "", "write Cairn-format findings JSON to this path")
	pf.StringVar(&f.exportContainers, "export-containers", "", "write the Kubernetes container inventory JSON (for Cepheus) to this path")
	pf.BoolVar(&f.validate, "validate", false, "opt-in: actively (read-only) confirm findings and capture evidence")
	pf.BoolVar(&f.captureSecrets, "capture-secrets", false, "AWS: retain raw control-plane secrets in-process so --validate can confirm AWS-key liveness (never written to disk or exported)")
	pf.StringVar(&f.rulesDir, "rules-dir", "", "directory of user policy-as-code rules to evaluate alongside the built-ins")

	return cmd
}

func runScan(ctx context.Context, f *scanFlags) error {
	provider := strings.ToLower(f.provider)
	if provider == "" {
		return fmt.Errorf("--provider is required (aws | azure | gcp | k8s)")
	}

	// AWS org-wide scanning takes a dedicated multi-account path (§9.4). The
	// single-account flow below is left untouched.
	if provider == "aws" && (f.org || len(f.accounts) > 0 || len(f.ous) > 0) {
		return runScanAWSOrg(ctx, f)
	}

	prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteractive)

	sc := &engine.ScanContext{Ctx: ctx, Provider: provider, Regions: f.regions}
	var account, identity string

	switch provider {
	case "aws":
		cfg, ident, path, err := auth.ResolveAWS(ctx, auth.AWSOptions{
			Profile:         f.profile,
			Region:          firstRegion(f.regions),
			MFASerial:       f.mfaSerial,
			MFAToken:        f.mfaToken,
			SessionDuration: f.sessionDur,
			AllowSSOLogin:   f.ssoLogin,
		}, prompter)
		if err != nil {
			return err
		}
		sc.AWS = cfg
		sc.Account = ident.Account
		account, identity = ident.Account, ident.ARN
		fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)

		// Resolve regions once, up front, so regional collectors fan out cleanly.
		if len(sc.Regions) == 0 {
			if regs, rerr := awsprovider.EnabledRegions(ctx, cfg); rerr == nil && len(regs) > 0 {
				sc.Regions = regs
			} else {
				sc.Regions = []string{cfg.Region}
			}
		}
		fmt.Fprintf(os.Stderr, "scanning %d region(s)\n", len(sc.Regions))

	case "azure":
		cred, err := auth.ResolveAzure(ctx, auth.AzureOptions{
			Method:       auth.AzureMethod(f.authMethod),
			TenantID:     f.tenantID,
			ClientID:     f.clientID,
			ClientSecret: f.clientSecret,
		}, prompter)
		if err != nil {
			return err
		}

		// Discover the subscriptions in scope (§9.4): enumerate, scope to a
		// management group / allowlist, drop excluded and disabled ones (with a
		// reason printed so a partial run never reads as full coverage).
		disc, err := discovery.AzureSubscriptions(ctx, cred, discovery.AzureOptions{
			Subscriptions:   f.subscriptions,
			Exclude:         f.excludeAccts,
			ManagementGroup: f.managementGroup,
		})
		if err != nil {
			return fmt.Errorf("enumerating subscriptions: %w", err)
		}
		for _, s := range disc.Skipped {
			fmt.Fprintf(os.Stderr, "  skip %s (%s): %s\n", s.ID, s.Name, s.Reason)
		}
		subs := disc.IDs()
		if len(subs) == 0 {
			return fmt.Errorf("no enabled Azure subscriptions in scope (%d skipped; use --subscription to specify one)", len(disc.Skipped))
		}
		sc.Azure = engine.AzureSession{Credential: cred, Subscriptions: subs}
		sc.Account = strings.Join(subs, ",")
		account = sc.Account
		fmt.Fprintf(os.Stderr, "authenticated to Azure; scanning %d subscription(s) (%d skipped)\n", len(subs), len(disc.Skipped))

	case "gcp":
		creds, err := auth.ResolveGCP(ctx)
		if err != nil {
			return err
		}
		// Discover the projects in scope (§9.4): enumerate, apply the allowlist /
		// exclude, and drop non-active ones (with a reason printed so a partial run
		// never reads as full coverage).
		disc, err := discovery.GCPProjects(ctx, creds, discovery.GCPOptions{
			Projects: f.projects,
			Exclude:  f.excludeAccts,
		})
		if err != nil {
			return fmt.Errorf("enumerating projects: %w", err)
		}
		for _, s := range disc.Skipped {
			fmt.Fprintf(os.Stderr, "  skip %s (%s): %s\n", s.ID, s.Name, s.Reason)
		}
		projects := disc.IDs()
		if len(projects) == 0 {
			return fmt.Errorf("no active GCP projects in scope (%d skipped; use --project to specify one)", len(disc.Skipped))
		}
		sc.GCP = engine.GCPSession{Credentials: creds, Projects: projects}
		sc.Account = strings.Join(projects, ",")
		account = sc.Account
		fmt.Fprintf(os.Stderr, "authenticated to GCP; scanning %d project(s) (%d skipped)\n", len(projects), len(disc.Skipped))

	case "k8s":
		// Estate mode (--org): scan every kubeconfig context, tolerating
		// unreachable ones. Otherwise scan the requested contexts (or current).
		var clusters []auth.K8sCluster
		if f.org {
			ok, failures, rerr := auth.ResolveK8sAll()
			if rerr != nil {
				return rerr
			}
			for _, fa := range failures {
				fmt.Fprintf(os.Stderr, "  skip context %s: %s\n", fa.Context, fa.Reason)
			}
			if len(ok) == 0 {
				return fmt.Errorf("no reachable kubeconfig context to scan (%d skipped)", len(failures))
			}
			clusters = ok
		} else {
			var err error
			if clusters, err = auth.ResolveK8s(f.contexts); err != nil {
				return err
			}
		}
		ctxNames := make([]string, len(clusters))
		engineClusters := make([]engine.K8sCluster, len(clusters))
		for i, c := range clusters {
			ctxNames[i] = c.Context
			engineClusters[i] = engine.K8sCluster{Context: c.Context, Config: c.Config}
		}
		sc.K8s = engine.K8sSession{Clusters: engineClusters}
		sc.Account = strings.Join(ctxNames, ",")
		account = sc.Account
		fmt.Fprintf(os.Stderr, "authenticated to Kubernetes; scanning %d context(s)\n", len(clusters))

	default:
		return fmt.Errorf("unsupported provider %q", provider)
	}

	// Load any user-supplied policy-as-code rules for the rules engine to pick up.
	ruleschecks.SetUserRulesDir(f.rulesDir)

	// Opt-in raw-secret capture (--capture-secrets): retain AWS key material the
	// secrets collector recovers so --validate can confirm liveness. In-process
	// only — never persisted; discarded when this command returns.
	var capture *secrets.Capture
	if f.captureSecrets && provider == "aws" {
		capture = secrets.NewCapture()
		sc.SecretSink = capture
	}

	started := time.Now().UTC()
	sc.Progress = &cliProgress{} // honest per-phase progress to stderr (real totals)
	result := engine.Run(sc)

	// Opt-in active validation (read-only): confirm findings and attach evidence
	// before persistence so it is stored and exported. Off unless --validate.
	if f.validate {
		progress.ReportPhase(sc.Progress, progress.PhaseValidate, "")
		var venv validate.Env
		var keyLiveness []validate.KeyLiveness
		if provider == "aws" {
			venv = validate.NewAWSEnv(sc.AWS) // authenticated, MFA-satisfied scan session
			if capture != nil {
				venv.CapturedAWSKeys = capture.AWSKeys()
				venv.AWSKeyProber = validate.NewAWSKeyProber()
				// Probe captured-key liveness once; both the exposed-secret evidence
				// and the attack-chain synthesis below consume the same results.
				if lv, perr := validate.ProbeCapturedKeys(ctx, venv.CapturedAWSKeys, venv.AWSKeyProber); perr != nil {
					fmt.Fprintf(os.Stderr, "  validation error: %v\n", perr)
				} else {
					keyLiveness = lv
					venv.CapturedKeyLiveness = lv
				}
			}
		}
		rep := validate.Run(ctx, result.Findings, validate.Options{Env: venv})
		fmt.Fprintf(os.Stderr, "validation: %d confirmed of %d attempted\n", rep.Confirmed, rep.Attempted)
		for _, e := range rep.Errors {
			fmt.Fprintf(os.Stderr, "  validation error: %v\n", e)
		}
		synthesizeChains(result, keyLiveness)
	}

	finished := time.Now().UTC()

	// Persist.
	progress.ReportPhase(sc.Progress, progress.PhasePersist, "")
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	scanID := newScanID()
	if err := st.CreateScan(ctx, scanID, provider, account, identity, started); err != nil {
		return err
	}
	if err := st.SaveFindings(ctx, scanID, result.Findings, finished); err != nil {
		return err
	}
	if err := st.SaveGraph(ctx, scanID, result.Graph); err != nil {
		return err
	}

	// Optional Cairn export.
	if f.exportPath != "" {
		out, err := os.Create(f.exportPath)
		if err != nil {
			return fmt.Errorf("creating export file: %w", err)
		}
		defer out.Close()
		if err := export.Cairn(out, provider, account, result.Findings, finished); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "exported %d findings to %s\n", len(result.Findings), f.exportPath)
	}

	// Optional container-inventory export for Cepheus (nubicustos-containers.json).
	if f.exportContainers != "" {
		out, err := os.Create(f.exportContainers)
		if err != nil {
			return fmt.Errorf("creating container-export file: %w", err)
		}
		defer out.Close()
		if err := export.Containers(out, result.State, finished); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "exported container inventory to %s\n", f.exportContainers)
	}

	printSummary(result, scanID)
	return nil
}

// runScanAWSOrg enumerates the AWS organization off one MFA-satisfied base
// session and scans every in-scope member account, attributing each to its own
// scan row (§9.4). Accounts scan in parallel (bounded); only persistence is
// serialized, since the embedded SQLite has no concurrent-writer guard.
func runScanAWSOrg(ctx context.Context, f *scanFlags) error {
	prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteractive)

	cfg, ident, path, err := auth.ResolveAWS(ctx, auth.AWSOptions{
		Profile:         f.profile,
		Region:          firstRegion(f.regions),
		MFASerial:       f.mfaSerial,
		MFAToken:        f.mfaToken,
		SessionDuration: f.sessionDur,
		AllowSSOLogin:   f.ssoLogin,
	}, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)

	disc, err := discovery.AWSAccounts(ctx, cfg, discovery.AWSOptions{
		RoleName:    f.orgRole,
		Accounts:    f.accounts,
		Exclude:     f.excludeAccts,
		OUs:         f.ous,
		IncludeMgmt: f.includeMgmt,
		Region:      firstRegion(f.regions),
		Validate:    true,
	})
	if err != nil {
		return err
	}

	for _, s := range disc.Skipped {
		fmt.Fprintf(os.Stderr, "  skip %s (%s): %s\n", s.ID, s.Name, s.Reason)
	}
	if len(disc.Accounts) == 0 {
		return fmt.Errorf("no accounts in scope to scan (%d skipped)", len(disc.Skipped))
	}
	conc := accountConcurrency(f)
	fmt.Fprintf(os.Stderr, "scanning %d account(s) across the organization (%d skipped), %d at a time\n",
		len(disc.Accounts), len(disc.Skipped), conc)

	// Load user policy-as-code rules once; the rules check reads this at evaluation.
	ruleschecks.SetUserRulesDir(f.rulesDir)

	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	var (
		mu        sync.Mutex // guards persistence + summaries + stderr lines
		summaries []orgAccountSummary
	)
	report := func(acc discovery.Account, s orgAccountSummary) {
		summaries = append(summaries, s)
		if s.err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s (%s): %v\n", acc.ID, acc.Name, s.err)
			return
		}
		fmt.Fprintf(os.Stderr, "  ✓ %s (%s): %d finding(s), %d path(s)%s\n",
			acc.ID, acc.Name, s.findings, s.paths, errSuffix(s.scanErrs))
	}

	runAccountPool(disc.Accounts, conc, func(acc discovery.Account) {
		s := scanOneAccount(ctx, f, st, &mu, acc)
		mu.Lock()
		report(acc, s)
		mu.Unlock()
	})

	printOrgSummary(disc, summaries)
	return nil
}

// orgAccountSummary is one account's outcome in an org-wide scan.
type orgAccountSummary struct {
	id, name, scanID string
	findings, paths  int
	scanErrs         int                       // non-fatal collector/check errors
	counts           map[findings.Severity]int // severity histogram
	err              error                     // fatal for this account (persistence/export failed)
}

// scanOneAccount runs the engine against one account and persists the result.
// persistMu serializes the database writes across the concurrent account pool.
func scanOneAccount(ctx context.Context, f *scanFlags, st *store.Store, persistMu *sync.Mutex, acc discovery.Account) orgAccountSummary {
	sum := orgAccountSummary{id: acc.ID, name: acc.Name}

	// Resolve regions per account — enabled regions can differ across the estate.
	regions := f.regions
	if len(regions) == 0 {
		if regs, rerr := awsprovider.EnabledRegions(ctx, acc.Config); rerr == nil && len(regs) > 0 {
			regions = regs
		} else {
			regions = []string{acc.Config.Region}
		}
	}

	sc := &engine.ScanContext{
		Ctx:      ctx,
		Provider: "aws",
		Account:  acc.ID,
		Regions:  regions,
		AWS:      acc.Config,
	}

	var capture *secrets.Capture
	if f.captureSecrets {
		capture = secrets.NewCapture()
		sc.SecretSink = capture
	}

	started := time.Now().UTC()
	result := engine.Run(sc)

	if f.validate {
		// Confirm findings read-only against this account's own session; evidence
		// attaches to the findings before they are persisted/exported.
		venv := validate.NewAWSEnv(acc.Config)
		var keyLiveness []validate.KeyLiveness
		if capture != nil {
			venv.CapturedAWSKeys = capture.AWSKeys()
			venv.AWSKeyProber = validate.NewAWSKeyProber()
			if lv, perr := validate.ProbeCapturedKeys(ctx, venv.CapturedAWSKeys, venv.AWSKeyProber); perr == nil {
				keyLiveness = lv
				venv.CapturedKeyLiveness = lv
			}
		}
		validate.Run(ctx, result.Findings, validate.Options{Env: venv})
		synthesizeChains(result, keyLiveness)
	}
	finished := time.Now().UTC()

	identity := acc.Identity
	if identity == "" {
		identity = acc.ID
	}
	scanID := newScanID()

	persistMu.Lock()
	err := func() error {
		if err := st.CreateScan(ctx, scanID, "aws", acc.ID, identity, started); err != nil {
			return err
		}
		if err := st.SaveFindings(ctx, scanID, result.Findings, finished); err != nil {
			return err
		}
		return st.SaveGraph(ctx, scanID, result.Graph)
	}()
	persistMu.Unlock()
	if err != nil {
		sum.err = fmt.Errorf("persist: %w", err)
		return sum
	}

	if f.exportPath != "" {
		if err := exportAccountCairn(f.exportPath, acc.ID, result.Findings, finished); err != nil {
			sum.err = fmt.Errorf("export: %w", err)
			return sum
		}
	}

	sum.scanID = scanID
	sum.findings = len(result.Findings)
	if result.Graph != nil {
		sum.paths = len(result.Graph.Paths)
	}
	sum.scanErrs = len(result.Errors)
	sum.counts = severityCounts(result.Findings)
	return sum
}

// exportAccountCairn writes one account's findings to a per-account Cairn file,
// derived from the --export path by inserting the account id before the extension.
func exportAccountCairn(base, accountID string, fs []findings.Finding, finishedAt time.Time) error {
	out, err := os.Create(accountExportPath(base, accountID))
	if err != nil {
		return err
	}
	defer out.Close()
	return export.Cairn(out, "aws", accountID, fs, finishedAt)
}

// accountExportPath turns "findings.json" + "222..." into "findings.222....json".
func accountExportPath(base, accountID string) string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return stem + "." + accountID + ext
}

// accountConcurrency clamps the per-account parallelism to at least 1.
func accountConcurrency(f *scanFlags) int {
	if f.acctConcurrency < 1 {
		return 1
	}
	return f.acctConcurrency
}

// runAccountPool runs fn over accounts with a bounded number of workers.
func runAccountPool(accs []discovery.Account, workers int, fn func(discovery.Account)) {
	if len(accs) == 0 {
		return
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, a := range accs {
		wg.Add(1)
		sem <- struct{}{}
		go func(a discovery.Account) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(a)
		}(a)
	}
	wg.Wait()
}

// severityCounts builds a severity histogram for a finding set.
func severityCounts(fs []findings.Finding) map[findings.Severity]int {
	counts := map[findings.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	return counts
}

// errSuffix annotates a per-account line when non-fatal scan errors occurred.
func errSuffix(n int) string {
	if n > 0 {
		return fmt.Sprintf(" — %d non-fatal error(s)", n)
	}
	return ""
}

// printOrgSummary prints the estate-wide rollup: per-account lines plus totals,
// keeping the skipped count visible so a partial run never reads as full coverage.
func printOrgSummary(disc *discovery.AWSResult, summaries []orgAccountSummary) {
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].id < summaries[j].id })

	totals := map[findings.Severity]int{}
	totalFindings, totalPaths, failed := 0, 0, 0
	for _, s := range summaries {
		if s.err != nil {
			failed++
			continue
		}
		totalFindings += s.findings
		totalPaths += s.paths
		for sev, n := range s.counts {
			totals[sev] += n
		}
	}

	fmt.Printf("\nOrg scan — %d account(s), %d finding(s), %d attack path(s)\n",
		len(summaries), totalFindings, totalPaths)
	if failed > 0 {
		fmt.Printf("  ⚠ %d account(s) failed to scan (see stderr)\n", failed)
	}
	if len(disc.Skipped) > 0 {
		fmt.Printf("  %d account(s) skipped (not in scope — see stderr)\n", len(disc.Skipped))
	}
	for _, sev := range []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow, findings.SeverityInfo,
	} {
		if totals[sev] > 0 {
			fmt.Printf("  %-8s %d\n", sev, totals[sev])
		}
	}
	for _, s := range summaries {
		if s.err != nil {
			fmt.Printf("  [FAILED]  %s (%s) — %v\n", s.id, s.name, s.err)
			continue
		}
		fmt.Printf("  %s (%s) — %d finding(s), %d path(s)%s [%s]\n",
			s.id, s.name, s.findings, s.paths, errSuffix(s.scanErrs), s.scanID)
	}
}

// synthesizeChains splices the flagship runtime-proven attack chains into a scan
// result: for each captured AWS key proven live, if the identity it maps to can
// escalate to admin, it appends a critical finding and merges a scored path into
// the graph. No-op unless --capture-secrets surfaced live keys for an AWS scan.
// Result findings are re-sorted so a synthesized critical chain leads the summary.
func synthesizeChains(result *engine.Result, keyLiveness []validate.KeyLiveness) {
	if result == nil || result.State == nil || len(keyLiveness) == 0 {
		return
	}
	var live []chain.LiveKey
	for _, kl := range keyLiveness {
		if kl.Live {
			live = append(live, chain.LiveKey{Cred: kl.Cred, ARN: kl.ARN, Account: kl.Account})
		}
	}
	if len(live) == 0 {
		return
	}
	cf, cp := chain.Synthesize(result.State.AWS, live, time.Now().UTC())
	if len(cf) == 0 {
		return
	}
	result.Findings = append(result.Findings, cf...)
	sort.SliceStable(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity.Rank() != result.Findings[j].Severity.Rank() {
			return result.Findings[i].Severity.Rank() > result.Findings[j].Severity.Rank()
		}
		return result.Findings[i].ID < result.Findings[j].ID
	})
	result.Graph.MergePaths(cp)
	fmt.Fprintf(os.Stderr, "attack-chain synthesis: %d runtime-proven exposed-key privilege-escalation chain(s)\n", len(cf))
}

// firstRegion returns the first region or "" — STS/global resolution only needs one.
func firstRegion(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	return regions[0]
}

// cliProgress prints one concise line per scan phase to stderr with the real
// unit total (never a timer-driven bar). It announces each phase once; the
// live count-up is for the TUI/web consumers. Safe for concurrent calls.
type cliProgress struct {
	mu        sync.Mutex
	announced map[progress.Phase]bool
}

func (p *cliProgress) Report(e progress.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.announced == nil {
		p.announced = map[progress.Phase]bool{}
	}
	if p.announced[e.Phase] {
		return
	}
	p.announced[e.Phase] = true
	if e.Total > 0 {
		fmt.Fprintf(os.Stderr, "  %s (%d)\n", phaseLabel(e.Phase), e.Total)
	} else {
		fmt.Fprintf(os.Stderr, "  %s\n", phaseLabel(e.Phase))
	}
}

func phaseLabel(p progress.Phase) string {
	switch p {
	case progress.PhaseCollect:
		return "collecting cloud configuration"
	case progress.PhaseCheck:
		return "running posture checks"
	case progress.PhaseReachability:
		return "solving network reachability"
	case progress.PhaseGraph:
		return "building attack-path graph"
	case progress.PhaseValidate:
		return "active validation"
	case progress.PhasePersist:
		return "persisting results"
	default:
		return string(p)
	}
}

// newScanID returns a sortable, collision-resistant scan id.
func newScanID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "scan-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func printSummary(r *engine.Result, scanID string) {
	counts := map[findings.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	paths := 0
	if r.Graph != nil {
		paths = len(r.Graph.Paths)
	}
	fmt.Printf("\nScan %s — %d findings, %d attack path(s) (%d collectors, %d checks)\n",
		scanID, len(r.Findings), paths, r.Collectors, r.Checks)
	// Surface collection/check failures on the stdout headline too — a result is
	// not "clean" if part of the scan failed; an error count buried only on
	// stderr can read as a green scan in captured output.
	if n := len(r.Errors); n > 0 {
		fmt.Printf("  ⚠ %d non-fatal error(s) — results may be incomplete (see stderr)\n", n)
	}
	for _, sev := range []findings.Severity{
		findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow, findings.SeverityInfo,
	} {
		if counts[sev] > 0 {
			fmt.Printf("  %-8s %d\n", sev, counts[sev])
		}
	}
	for _, f := range r.Findings {
		scope := f.Resource.ID
		if n := len(f.Affected); n > 0 {
			scope = fmt.Sprintf("%d affected", n)
		}
		fmt.Printf("  [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Title, scope)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d non-fatal error(s) during scan:\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", e)
		}
	}
}
