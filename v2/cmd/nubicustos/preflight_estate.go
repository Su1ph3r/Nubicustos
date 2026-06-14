package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/oauth2/google"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/discovery"
	"github.com/Su1ph3r/nubicustos/internal/preflight"
	gcpprovider "github.com/Su1ph3r/nubicustos/internal/providers/gcp"
)

// runPreflightAWSOrg verifies estate-wide scan access: it confirms the base
// identity can enumerate the organization and assume into members, then checks
// every in-scope member account's *own* assumed session for the scan
// permissions — so a "ready" estate verdict means the scan will actually run in
// each account, not merely that the base could reach them.
func runPreflightAWSOrg(ctx context.Context, f *preflightFlags) error {
	// Per-member tool set: the selected scan tools' native actions, with no org
	// actions appended (members are scanned, they do not enumerate).
	memberTools, err := selectTools(f.tools, false)
	if err != nil {
		return err
	}

	prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteract)
	cfg, ident, path, err := auth.ResolveAWS(ctx, auth.AWSOptions{
		Profile:       f.profile,
		Region:        f.region,
		MFASerial:     f.mfaSerial,
		MFAToken:      f.mfaToken,
		AllowSSOLogin: f.ssoLogin,
	}, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)

	// Base check: the enumeration + assume access on the management/base identity.
	// Explicit --accounts skips Organizations enumeration, so it needs only
	// sts:AssumeRole; --org / --ou enumerate and need the organizations:* reads
	// too (all granted by AWSOrganizationsReadOnlyAccess).
	enumerate := len(f.accounts) == 0
	native, _ := preflight.AWSToolByKey("nubicustos")
	baseTool := preflight.AWSToolWithMemberAssume(native)
	if enumerate {
		baseTool = preflight.AWSToolWithOrg(native, true)
	}
	baseOpts := preflight.Options{
		Provider:  "aws",
		Identity:  ident.ARN,
		Account:   ident.Account,
		Tools:     []preflight.Tool{baseTool},
		Simulator: iam.NewFromConfig(cfg),
	}
	if !f.noProbe {
		baseOpts.Prober = preflight.NewAWSProber(cfg)
	}
	base := preflight.Evaluate(ctx, baseOpts)

	// Enumerate the estate off the validated base session.
	disc, err := discovery.AWSAccounts(ctx, cfg, discovery.AWSOptions{
		RoleName:    f.orgRole,
		Accounts:    f.accounts,
		Exclude:     f.excludeAccts,
		OUs:         f.ous,
		IncludeMgmt: f.includeMgmt,
		Region:      f.region,
		Validate:    true,
	})
	if err != nil {
		return err
	}

	// Zero reachable members is not a ready estate, even if the base can
	// enumerate — nothing was actually verified. Surface why, then fail.
	if len(disc.Accounts) == 0 {
		for _, s := range disc.Skipped {
			fmt.Fprintf(os.Stderr, "  skip %s (%s): %s\n", s.ID, s.Name, s.Reason)
		}
		return fmt.Errorf("no member accounts in scope to check (%d skipped); base enumeration access was %s", len(disc.Skipped), base.Overall)
	}

	fmt.Fprintf(os.Stderr, "checking %d member account(s) (%d skipped)\n", len(disc.Accounts), len(disc.Skipped))

	// Check each reachable member against its own assumed session, in parallel.
	reports := make([]preflight.AccountReport, len(disc.Accounts))
	checkMembersParallel(disc.Accounts, f.acctConcurrency, func(i int, acc discovery.Account) {
		opts := preflight.Options{
			Provider:  "aws",
			Identity:  acc.Identity,
			Account:   acc.ID,
			Tools:     memberTools,
			Simulator: iam.NewFromConfig(acc.Config),
		}
		if !f.noProbe {
			opts.Prober = preflight.NewAWSProber(acc.Config)
		}
		reports[i] = preflight.AccountReport{
			ID:         acc.ID,
			Name:       acc.Name,
			Management: acc.Management,
			Report:     preflight.Evaluate(ctx, opts),
		}
	})

	est := preflight.EstateReport{
		Provider: "aws",
		Scope:    awsScopeLabel(f),
		Base:     &base,
		Accounts: reports,
		Skipped:  toSkippedAccounts(disc.Skipped),
	}
	est.Overall = preflight.EstateOverall(est.Base, est.Accounts)
	return emitEstatePreflight(f, est)
}

// runPreflightAzureEstate checks every in-scope subscription. Azure needs no base
// check: one credential already spans the estate (no per-member role to assume).
func runPreflightAzureEstate(ctx context.Context, f *preflightFlags) error {
	tools, err := selectAzureTools(f.tools)
	if err != nil {
		return err
	}

	prompter := auth.NewCLIPrompter("", !f.nonInteract)
	cred, err := auth.ResolveAzure(ctx, auth.AzureOptions{
		Method:       auth.AzureMethod(f.authMethod),
		TenantID:     f.tenantID,
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
	}, prompter)
	if err != nil {
		return err
	}

	disc, err := discovery.AzureSubscriptions(ctx, cred, discovery.AzureOptions{
		Exclude:         f.excludeAccts,
		ManagementGroup: f.managementGroup,
	})
	if err != nil {
		return err
	}
	if len(disc.Subscriptions) == 0 {
		return fmt.Errorf("no in-scope subscription visible to this identity (%d skipped)", len(disc.Skipped))
	}
	fmt.Fprintf(os.Stderr, "authenticated to Azure; checking %d subscription(s)\n", len(disc.Subscriptions))

	reports := make([]preflight.AccountReport, len(disc.Subscriptions))
	checkMembersParallel(disc.Subscriptions, f.acctConcurrency, func(i int, sub discovery.AzureSubscription) {
		opts := preflight.Options{
			Provider:   "azure",
			Identity:   "Azure credential",
			Account:    sub.ID,
			Tools:      tools,
			Prober:     preflight.NewAzureProber(cred, sub.ID),
			Remediator: preflight.NewAzureRemediator(sub.ID),
		}
		reports[i] = preflight.AccountReport{ID: sub.ID, Name: sub.Name, Report: preflight.Evaluate(ctx, opts)}
	})

	est := preflight.EstateReport{
		Provider: "azure",
		Scope:    azureScopeLabel(f),
		Accounts: reports,
		Skipped:  toSkippedAccounts(disc.Skipped),
	}
	est.Overall = preflight.EstateOverall(nil, est.Accounts)
	return emitEstatePreflight(f, est)
}

// runPreflightGCPEstate checks every enabled project the credential can see.
func runPreflightGCPEstate(ctx context.Context, f *preflightFlags, creds *google.Credentials, tools []preflight.Tool) error {
	projects, err := gcpprovider.EnabledProjects(ctx, creds)
	if err != nil {
		return fmt.Errorf("listing enabled projects: %w", err)
	}
	if len(projects) == 0 {
		return fmt.Errorf("no active project visible to this identity")
	}
	fmt.Fprintf(os.Stderr, "authenticated to GCP; checking %d project(s)\n", len(projects))

	reports := make([]preflight.AccountReport, len(projects))
	checkMembersParallel(projects, f.acctConcurrency, func(i int, project string) {
		opts := preflight.Options{
			Provider:   "gcp",
			Identity:   "GCP credential",
			Account:    project,
			Tools:      tools,
			Prober:     preflight.NewGCPProber(ctx, creds, project),
			Remediator: preflight.NewGCPRemediator(project),
		}
		reports[i] = preflight.AccountReport{ID: project, Report: preflight.Evaluate(ctx, opts)}
	})

	est := preflight.EstateReport{Provider: "gcp", Scope: "projects", Accounts: reports}
	est.Overall = preflight.EstateOverall(nil, est.Accounts)
	return emitEstatePreflight(f, est)
}

// runPreflightK8sEstate checks every kubeconfig context. A context that cannot be
// built or reached is recorded as skipped, never aborting the run.
func runPreflightK8sEstate(ctx context.Context, f *preflightFlags, tools []preflight.Tool) error {
	clusters, failures, err := auth.ResolveK8sAll()
	if err != nil {
		return err
	}

	// Seed the skip list with contexts that failed to build or were unreachable,
	// so they show in the report with a reason instead of silently vanishing.
	skipped := make([]preflight.SkippedAccount, 0, len(failures))
	for _, fa := range failures {
		skipped = append(skipped, preflight.SkippedAccount{ID: fa.Context, Reason: fa.Reason})
	}

	if len(clusters) == 0 {
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "  skip %s: %s\n", s.ID, s.Reason)
		}
		return fmt.Errorf("no reachable kubeconfig context to check (%d skipped)", len(skipped))
	}
	fmt.Fprintf(os.Stderr, "checking %d Kubernetes context(s) (%d skipped)\n", len(clusters), len(skipped))

	var (
		reports []preflight.AccountReport
		mu      sync.Mutex
	)
	checkMembersParallel(clusters, f.acctConcurrency, func(_ int, cl auth.K8sCluster) {
		prober, perr := preflight.NewK8sProber(cl.Config)
		if perr != nil {
			mu.Lock()
			skipped = append(skipped, preflight.SkippedAccount{ID: cl.Context, Reason: "building client: " + perr.Error()})
			mu.Unlock()
			return
		}
		rep := preflight.Evaluate(ctx, preflight.Options{
			Provider:   "k8s",
			Identity:   "Kubernetes credential",
			Account:    cl.Context,
			Tools:      tools,
			Prober:     prober,
			Remediator: preflight.NewK8sRemediator(),
		})
		mu.Lock()
		reports = append(reports, preflight.AccountReport{ID: cl.Context, Report: rep})
		mu.Unlock()
	})

	est := preflight.EstateReport{Provider: "k8s", Scope: "contexts", Accounts: reports, Skipped: skipped}
	est.Overall = preflight.EstateOverall(nil, est.Accounts)
	return emitEstatePreflight(f, est)
}

// emitEstatePreflight writes remediation policies (optionally), renders the
// estate report, and gates the exit code on the worst-case readiness.
func emitEstatePreflight(f *preflightFlags, est preflight.EstateReport) error {
	if f.writePolicies != "" {
		if err := writeEstateRemediationPolicies(f.writePolicies, est); err != nil {
			return err
		}
	}

	if f.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(est); err != nil {
			return err
		}
	} else {
		printEstatePreflight(os.Stdout, est)
	}

	if est.Overall != preflight.ReadinessReady {
		return fmt.Errorf("preflight: estate access is %s (see report above)", est.Overall)
	}
	return nil
}

// printEstatePreflight renders the estate rollup: the base enumeration check (if
// any), a per-member readiness line, the skipped members with reasons, and the
// worst-case overall verdict.
func printEstatePreflight(w *os.File, est preflight.EstateReport) {
	fmt.Fprintf(w, "ESTATE PREFLIGHT — %s · %s\n\n", est.Provider, est.Scope)

	if est.Base != nil {
		bt := est.Base.Tools[0]
		fmt.Fprintf(w, "base %s (account %s): %s — %s\n\n",
			est.Base.Identity, est.Base.Account, strings.ToUpper(string(est.Base.Overall)), bt.Remediate.Summary)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, a := range est.Accounts {
		allowed, total := readinessTotals(a.Report)
		fmt.Fprintf(tw, "[%s]\t%s\t%s\t%d/%d permission(s)\n",
			strings.ToUpper(string(a.Report.Overall)), a.ID, a.Name, allowed, total)
	}
	tw.Flush()

	if len(est.Skipped) > 0 {
		fmt.Fprintf(w, "\nskipped (%d):\n", len(est.Skipped))
		for _, s := range est.Skipped {
			fmt.Fprintf(w, "  %s %s — %s\n", s.ID, s.Name, s.Reason)
		}
	}

	// Per-member detail for anything not ready, so an operator sees exactly what
	// is missing and where.
	for _, a := range est.Accounts {
		if a.Report.Overall == preflight.ReadinessReady {
			continue
		}
		fmt.Fprintf(w, "\n%s (%s) — %s\n", a.ID, a.Name, strings.ToUpper(string(a.Report.Overall)))
		for _, t := range a.Report.Tools {
			if t.Readiness == preflight.ReadinessReady {
				continue
			}
			fmt.Fprintf(w, "  %s\n", t.Remediate.Summary)
			if len(t.Denied) > 0 {
				fmt.Fprintf(w, "    missing: %s\n", strings.Join(t.Denied, ", "))
			}
			if len(t.Conflicts) > 0 {
				fmt.Fprintf(w, "    runtime-blocked (SCP/boundary): %s\n", strings.Join(t.Conflicts, ", "))
			}
			if len(t.Unknown) > 0 {
				fmt.Fprintf(w, "    undetermined: %s\n", strings.Join(t.Unknown, ", "))
			}
		}
	}

	fmt.Fprintf(w, "\nOVERALL: %s\n", strings.ToUpper(string(est.Overall)))
}

// readinessTotals sums allowed actions and total actions across a member's tools.
func readinessTotals(rep preflight.Report) (allowed, total int) {
	for _, t := range rep.Tools {
		allowed += len(t.Allowed)
		total += len(t.Actions)
	}
	return allowed, total
}

// writeEstateRemediationPolicies writes one <member>-<key>.policy.json per
// non-ready tool, namespaced by member id so accounts never clobber each other.
func writeEstateRemediationPolicies(dir string, est preflight.EstateReport) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating policy dir: %w", err)
	}
	write := func(member string, rep preflight.Report) error {
		for _, t := range rep.Tools {
			if t.Remediate.PolicyDocument == "" {
				continue
			}
			p := filepath.Join(dir, sanitizeMemberID(member)+"-"+t.Key+".policy.json")
			if err := os.WriteFile(p, []byte(t.Remediate.PolicyDocument), 0o600); err != nil {
				return fmt.Errorf("writing %s: %w", p, err)
			}
			fmt.Fprintf(os.Stderr, "wrote remediation policy for %s/%s → %s\n", member, t.Name, p)
		}
		return nil
	}
	if est.Base != nil {
		if err := write(est.Base.Account+"-base", *est.Base); err != nil {
			return err
		}
	}
	for _, a := range est.Accounts {
		if err := write(a.ID, a.Report); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeMemberID makes a member id safe as a filename component (kubeconfig
// contexts and ARNs can carry path separators).
func sanitizeMemberID(id string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(id)
}

// toSkippedAccounts maps discovery's skip records into the estate report shape.
func toSkippedAccounts(in []discovery.Skipped) []preflight.SkippedAccount {
	if len(in) == 0 {
		return nil
	}
	out := make([]preflight.SkippedAccount, len(in))
	for i, s := range in {
		out[i] = preflight.SkippedAccount{ID: s.ID, Name: s.Name, Reason: s.Reason}
	}
	return out
}

// awsScopeLabel describes the AWS estate scope for the report header.
func awsScopeLabel(f *preflightFlags) string {
	switch {
	case len(f.accounts) > 0:
		return fmt.Sprintf("%d explicit account(s)", len(f.accounts))
	case len(f.ous) > 0:
		return fmt.Sprintf("organizational unit(s) %s", strings.Join(f.ous, ", "))
	default:
		return "organization"
	}
}

// azureScopeLabel describes the Azure estate scope for the report header.
func azureScopeLabel(f *preflightFlags) string {
	if f.managementGroup != "" {
		return "management group " + f.managementGroup
	}
	return "subscriptions"
}

// checkMembersParallel runs fn over members with a bounded number of workers,
// passing each member's index so callers can write results into a preallocated
// slice without locking.
func checkMembersParallel[T any](members []T, workers int, fn func(int, T)) {
	if len(members) == 0 {
		return
	}
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range members {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i, members[i])
		}(i)
	}
	wg.Wait()
}
