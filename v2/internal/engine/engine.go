// Package engine is the scan orchestrator. Collectors and checks register
// themselves at init time; the scanner runs collectors concurrently to fill
// state, then runs checks concurrently to emit findings.
//
// The two-phase shape (collect-all, then check-all) mirrors the auth model:
// anything interactive or rate-sensitive happens before fan-out, and the
// concurrent phase is pure CPU + cached API reads.
package engine

import (
	"context"
	"runtime"
	"sort"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2/google"
	"k8s.io/client-go/rest"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/progress"
	"github.com/Su1ph3r/nubicustos/internal/reachability"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// ScanContext carries everything a collector/check needs for one scan target
// (one account/subscription). Provider-specific sessions live here.
type ScanContext struct {
	Ctx      context.Context
	Provider string // aws | azure | gcp | k8s
	Account  string
	Regions  []string

	// AWS holds the resolved, MFA-satisfied AWS config when Provider == "aws".
	AWS aws.Config

	// Azure holds the resolved credential and subscriptions when Provider == "azure".
	Azure AzureSession

	// GCP holds the resolved ADC credentials and projects when Provider == "gcp".
	GCP GCPSession

	// K8s holds the resolved per-context REST configs when Provider == "k8s".
	K8s K8sSession

	// Progress, if set, receives real per-phase progress as the scan runs
	// (collectors and checks report per completed unit; reachability and graph
	// report as indeterminate phases). Nil disables reporting. The reporter must
	// be safe for concurrent calls — collectors and checks run in a worker pool.
	Progress progress.Reporter

	// SecretSink, if set, receives raw secret material a collector recovers
	// from the control plane under the opt-in --capture-secrets, so the active-
	// validation pass can confirm liveness. Nil (the default) means capture is
	// off and no raw secret is ever retained. Must be safe for concurrent calls.
	SecretSink SecretSink
}

// SecretSink receives raw credentials captured during collection when the
// operator opts into --capture-secrets. Implemented by *secrets.Capture; kept as
// an interface here so the engine does not depend on the secrets package. Nil is
// the default (capture disabled). Implementations must be concurrency-safe.
type SecretSink interface {
	AddAWSKey(accessKeyID, secretAccessKey, sessionToken, surface, resource, region string)
}

// K8sSession carries the validated kubeconfig contexts in scope for the scan.
type K8sSession struct {
	Clusters []K8sCluster
}

// K8sCluster pairs a kubeconfig context name with its REST config.
type K8sCluster struct {
	Context string
	Config  *rest.Config
}

// AzureSession carries the validated Azure credential and the subscriptions in
// scope for the scan.
type AzureSession struct {
	Credential    azcore.TokenCredential
	Subscriptions []string
}

// GCPSession carries the validated Application Default Credentials and the
// projects in scope for the scan.
type GCPSession struct {
	Credentials *google.Credentials
	Projects    []string
}

// Collector reads cloud configuration into State. Implementations must no-op
// for providers they do not handle.
type Collector interface {
	Name() string
	Collect(sc *ScanContext, st *state.State) error
}

// Check evaluates collected State and emits findings. Checks must be pure with
// respect to State (read-only) and safe to run concurrently.
type Check interface {
	Spec() findings.CheckSpec
	Evaluate(sc *ScanContext, st *state.State) ([]findings.Finding, error)
}

var (
	regMu      sync.Mutex
	collectors []Collector
	checks     []Check
)

// RegisterCollector adds a collector to the global registry (call from init).
func RegisterCollector(c Collector) {
	regMu.Lock()
	defer regMu.Unlock()
	collectors = append(collectors, c)
}

// RegisterCheck adds a check to the global registry (call from init).
func RegisterCheck(c Check) {
	regMu.Lock()
	defer regMu.Unlock()
	checks = append(checks, c)
}

// Collectors returns a snapshot of the registered collectors.
func Collectors() []Collector {
	regMu.Lock()
	defer regMu.Unlock()
	return append([]Collector(nil), collectors...)
}

// Checks returns a snapshot of the registered checks.
func Checks() []Check {
	regMu.Lock()
	defer regMu.Unlock()
	return append([]Check(nil), checks...)
}

// Result is the outcome of a scan.
type Result struct {
	Findings   []findings.Finding
	Graph      *graph.Graph // attack-path graph derived from the collected state
	State      *state.State // the collected cloud state (e.g. for container-inventory export)
	Errors     []error      // non-fatal per-collector/check errors (partial-failure tolerant)
	Collectors int
	Checks     int
}

// concurrency bounds the worker pool; min(16, cores-2) per the plan.
func concurrency() int {
	n := runtime.NumCPU() - 2
	if n < 1 {
		n = 1
	}
	if n > 16 {
		n = 16
	}
	return n
}

// Run executes the full scan: collect (parallel) then check (parallel).
// Individual collector/check failures are collected as errors, never fatal —
// one account's AccessDenied must not abort the run.
func Run(sc *ScanContext) *Result {
	regMu.Lock()
	cs := append([]Collector(nil), collectors...)
	cks := append([]Check(nil), checks...)
	regMu.Unlock()
	return runScan(sc, cs, cks)
}

// runScan is the registry-independent core, taking explicit collector/check
// lists so it is testable with fakes. It reports real progress through
// sc.Progress: collect and check each emit one event per completed unit (true
// done/total), and reachability + graph report as indeterminate phases.
func runScan(sc *ScanContext, cs []Collector, cks []Check) *Result {
	st := state.New()
	st.SetAWSAccount(sc.Account)

	res := &Result{Collectors: len(cs), Checks: len(cks)}
	var mu sync.Mutex

	// Phase 1: collectors fill state. Report per completed collector.
	collectProg := progress.NewCounter(sc.Progress, progress.PhaseCollect, len(cs))
	runPool(cs, concurrency(), func(c Collector) {
		if err := c.Collect(sc, st); err != nil {
			mu.Lock()
			res.Errors = append(res.Errors, err)
			mu.Unlock()
		}
		collectProg.Done(c.Name())
	})

	// Phase 2: checks read state and emit findings. Report per completed check.
	checkProg := progress.NewCounter(sc.Progress, progress.PhaseCheck, len(cks))
	runPool(cks, concurrency(), func(ck Check) {
		fs, err := ck.Evaluate(sc, st)
		mu.Lock()
		if err != nil {
			res.Errors = append(res.Errors, err)
		}
		res.Findings = append(res.Findings, fs...)
		mu.Unlock()
		checkProg.Done(ck.Spec().ID)
	})

	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Severity.Rank() != res.Findings[j].Severity.Rank() {
			return res.Findings[i].Severity.Rank() > res.Findings[j].Severity.Rank()
		}
		return res.Findings[i].ID < res.Findings[j].ID
	})

	// Phase 3: solve network reachability, annotate exposure findings with it
	// (§9.5 false-positive reduction), then derive the attack-path graph from the
	// fully collected state with reachability applied. These have no knowable
	// per-unit total, so they report as indeterminate phases.
	progress.ReportPhase(sc.Progress, progress.PhaseReachability, "")
	rch := reachability.Solve(st.AWS)
	reachability.Annotate(res.Findings, st.AWS, rch)
	// Azure exposure findings get the same false-positive reduction: an NSG open
	// to the internet only matters if it governs a NIC with a public IP (§9.5).
	arch := reachability.SolveAzure(st.Azure)
	reachability.AnnotateAzure(res.Findings, st.Azure, arch)
	progress.ReportPhase(sc.Progress, progress.PhaseGraph, "")
	res.Graph = graph.Build(st, rch)
	res.State = st
	return res
}

// runPool runs fn over items with a bounded number of workers.
func runPool[T any](items []T, workers int, fn func(T)) {
	if len(items) == 0 {
		return
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(it)
		}(it)
	}
	wg.Wait()
}
