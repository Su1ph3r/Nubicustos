package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Decision is the verdict for a single action.
type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
	DecisionUnknown Decision = "unknown" // could not be determined
)

// Basis records how a decision was reached.
type Basis string

const (
	BasisSimulated Basis = "simulated"
	BasisProbed    Basis = "probed"
	BasisBoth      Basis = "both"
	BasisNone      Basis = "none"
)

// Readiness summarizes whether a tool can run with the current access.
type Readiness string

const (
	ReadinessReady      Readiness = "ready"      // every required action verified allowed
	ReadinessPartial    Readiness = "partial"    // some allowed, some denied
	ReadinessFailed     Readiness = "failed"     // no required action allowed, some denied
	ReadinessUnverified Readiness = "unverified" // no denials, but some required actions could not be verified
	ReadinessUnknown    Readiness = "unknown"    // nothing could be determined
)

// ActionResult is the verdict for one required action.
type ActionResult struct {
	Action   string   `json:"action"`
	Decision Decision `json:"decision"`
	Basis    Basis    `json:"basis"`
	// Conflict is set when simulation and the live probe disagreed — typically an
	// SCP or session policy denying at runtime what the identity's IAM policies
	// allow. Treated as denied (runtime wins) and surfaced prominently.
	Conflict bool   `json:"conflict,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Remediation is the client-ready fix for a tool's access gaps.
type Remediation struct {
	ManagedPolicies []string `json:"managed_policies,omitempty"` // attach any of these for a complete grant
	PolicyName      string   `json:"policy_name,omitempty"`      // name for the generated inline policy
	PolicyDocument  string   `json:"policy_document,omitempty"`  // JSON inline policy granting exactly the missing actions
	Summary         string   `json:"summary"`                    // one-line, client-facing
}

// ToolReport is the access result for one tool.
type ToolReport struct {
	Key       string         `json:"key"`
	Name      string         `json:"name"`
	Readiness Readiness      `json:"readiness"`
	Allowed   []string       `json:"allowed"`
	Denied    []string       `json:"denied"`
	Unknown   []string       `json:"unknown,omitempty"`
	Conflicts []string       `json:"conflicts,omitempty"`
	Actions   []ActionResult `json:"actions"`
	Remediate Remediation    `json:"remediation"`
}

// Report is the full preflight result for a credential.
type Report struct {
	Provider string       `json:"provider"`
	Identity string       `json:"identity"` // caller principal ARN
	Account  string       `json:"account"`
	Method   string       `json:"method"` // how access was determined
	Tools    []ToolReport `json:"tools"`
	Overall  Readiness    `json:"overall"`
}

// Simulator runs IAM policy simulation; satisfied by *iam.Client and faked in tests.
type Simulator interface {
	SimulatePrincipalPolicy(context.Context, *iam.SimulatePrincipalPolicyInput, ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// Prober reports whether a single action is permitted by attempting a
// representative read call (catching SCP/boundary denials simulation misses). It
// returns DecisionUnknown for actions it does not know how to probe. Implemented
// by the command layer (it owns the per-service clients); faked in tests.
type Prober interface {
	Probe(ctx context.Context, action string) Decision
}

// Options configures an evaluation.
type Options struct {
	Provider  string
	Identity  string // caller principal ARN (PolicySourceArn for simulation)
	Account   string
	Tools     []Tool
	Simulator Simulator // nil → simulation skipped (probe-only)
	Prober    Prober    // nil → probe cross-check skipped (simulation-only)
}

// simBatch caps actions per SimulatePrincipalPolicy call.
const simBatch = 100

// Evaluate verifies each tool's required access for the identity and builds the
// report. It is read-only. Simulation provides exact per-action allow/deny;
// the probe cross-checks and fills gaps. Either source may be absent.
func Evaluate(ctx context.Context, opts Options) Report {
	rep := Report{
		Provider: opts.Provider,
		Identity: opts.Identity,
		Account:  opts.Account,
		Method:   describeMethod(opts.Simulator != nil, opts.Prober != nil),
	}

	// Simulate the union of all actions once, then slice per tool.
	var simDecisions map[string]Decision
	simOK := false
	if opts.Simulator != nil {
		var err error
		simDecisions, err = simulate(ctx, opts.Simulator, opts.Identity, unionActions(opts.Tools))
		if err != nil {
			rep.Method = describeMethod(false, opts.Prober != nil) + " (simulation unavailable: " + condense(err.Error()) + ")"
		} else {
			simOK = true
		}
	}

	for _, t := range opts.Tools {
		rep.Tools = append(rep.Tools, evaluateTool(ctx, t, simDecisions, simOK, opts.Prober))
	}
	rep.Overall = overallReadiness(rep.Tools)
	return rep
}

func evaluateTool(ctx context.Context, t Tool, sim map[string]Decision, simOK bool, prober Prober) ToolReport {
	tr := ToolReport{Key: t.Key, Name: t.Name}
	for _, action := range t.RequiredActions {
		ar := ActionResult{Action: action, Decision: DecisionUnknown, Basis: BasisNone}

		var simD Decision = DecisionUnknown
		if simOK {
			if d, ok := sim[action]; ok {
				simD = d
			}
		}
		var probeD Decision = DecisionUnknown
		if prober != nil {
			probeD = prober.Probe(ctx, action)
		}

		switch {
		case simD != DecisionUnknown && probeD != DecisionUnknown:
			ar.Basis = BasisBoth
			if simD == probeD {
				ar.Decision = simD
			} else {
				// Runtime wins: a probe-deny over a simulate-allow is an SCP/boundary
				// block; either disagreement is a real, reportable risk.
				ar.Decision = DecisionDenied
				ar.Conflict = true
				ar.Note = "simulation and live probe disagreed (SCP/permission boundary suspected) — treated as denied"
			}
		case simD != DecisionUnknown:
			ar.Decision, ar.Basis = simD, BasisSimulated
		case probeD != DecisionUnknown:
			ar.Decision, ar.Basis = probeD, BasisProbed
		}

		tr.Actions = append(tr.Actions, ar)
		switch ar.Decision {
		case DecisionAllowed:
			tr.Allowed = append(tr.Allowed, action)
		case DecisionDenied:
			tr.Denied = append(tr.Denied, action)
			if ar.Conflict {
				tr.Conflicts = append(tr.Conflicts, action)
			}
		default:
			tr.Unknown = append(tr.Unknown, action)
		}
	}

	tr.Readiness = toolReadiness(tr)
	tr.Remediate = buildRemediation(t, tr)
	return tr
}

// toolReadiness classifies a tool. A required action that could not be verified
// (neither simulated nor probed) is "unknown", and unknowns must never be
// absorbed into a "ready" verdict — that would certify access the check never
// confirmed. So: any denial → partial (with some allowed) or failed (none
// allowed); no denials but unverified actions remain → unverified; every action
// verified-allowed → ready; nothing in scope or determinable → unknown.
func toolReadiness(tr ToolReport) Readiness {
	switch {
	case len(tr.Denied) > 0 && len(tr.Allowed) > 0:
		return ReadinessPartial
	case len(tr.Denied) > 0:
		return ReadinessFailed // allowed == 0
	case len(tr.Unknown) > 0:
		return ReadinessUnverified // no denials, but coverage is incomplete
	case len(tr.Allowed) > 0:
		return ReadinessReady // every action verified allowed, none unknown
	default:
		return ReadinessUnknown // nothing in scope
	}
}

func overallReadiness(tools []ToolReport) Readiness {
	worst := ReadinessReady
	// Anything other than fully-ready must not present as ready. Unverified and
	// unknown both mean "not confirmed" and outrank ready for gating.
	rank := map[Readiness]int{
		ReadinessReady: 0, ReadinessUnverified: 1, ReadinessUnknown: 2,
		ReadinessPartial: 3, ReadinessFailed: 4,
	}
	for _, t := range tools {
		if rank[t.Readiness] > rank[worst] {
			worst = t.Readiness
		}
	}
	return worst
}

// buildRemediation produces the client-facing fix, distinguishing three kinds
// of gap: IAM permissions the identity lacks (fixable by attaching a policy),
// permissions IAM allows but the runtime blocks via an SCP/boundary (needs an
// org-level change, not a policy attach), and permissions that could not be
// verified at all. The generated inline policy grants only the genuinely
// IAM-missing actions — granting a runtime-blocked one would not unblock it.
func buildRemediation(t Tool, tr ToolReport) Remediation {
	// Surface managed policies as full ARNs so the client report is directly
	// attachable (`aws iam attach-*-policy --policy-arn ...`); fall back to the
	// short name if the ARN is unknown.
	r := Remediation{PolicyName: t.RemediationPolicyName}
	for _, name := range t.RequiredManagedPolicies {
		if arn, ok := AWSManagedPolicyARN[name]; ok {
			r.ManagedPolicies = append(r.ManagedPolicies, arn)
		} else {
			r.ManagedPolicies = append(r.ManagedPolicies, name)
		}
	}
	if tr.Readiness == ReadinessReady {
		r.Summary = fmt.Sprintf("%s: all %d required permission(s) present — ready.", t.Name, len(tr.Allowed))
		return r
	}

	// Conflicts (IAM-allowed but runtime-denied) are a subset of Denied; exclude
	// them from the IAM-missing set since a policy attach cannot fix an SCP block.
	conflict := make(map[string]bool, len(tr.Conflicts))
	for _, c := range tr.Conflicts {
		conflict[c] = true
	}
	var iamMissing []string
	for _, d := range tr.Denied {
		if !conflict[d] {
			iamMissing = append(iamMissing, d)
		}
	}
	sort.Strings(iamMissing)
	if len(iamMissing) > 0 {
		r.PolicyDocument = inlinePolicy(t.RemediationPolicyName, iamMissing)
	}

	var parts []string
	if len(iamMissing) > 0 {
		fix := fmt.Sprintf("apply the generated %s inline policy", t.RemediationPolicyName)
		if len(t.RequiredManagedPolicies) > 0 {
			fix = fmt.Sprintf("attach %s, or %s", strings.Join(t.RequiredManagedPolicies, " / "), fix)
		}
		parts = append(parts, fmt.Sprintf("missing %d IAM permission(s) — %s", len(iamMissing), fix))
	}
	if len(tr.Conflicts) > 0 {
		parts = append(parts, fmt.Sprintf("%d permission(s) IAM-allowed but blocked at runtime (SCP/permission boundary) — requires an org/SCP change, not a policy attachment", len(tr.Conflicts)))
	}
	if len(tr.Unknown) > 0 {
		parts = append(parts, fmt.Sprintf("%d permission(s) could not be verified — grant iam:SimulatePrincipalPolicy for an authoritative check", len(tr.Unknown)))
	}
	r.Summary = fmt.Sprintf("%s [%s]: %s.", t.Name, tr.Readiness, strings.Join(parts, "; "))
	return r
}

// inlinePolicy renders a least-privilege IAM policy granting exactly actions.
func inlinePolicy(sid string, actions []string) string {
	if sid == "" {
		sid = "NubicustosPreflightGrant"
	}
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":      sid,
			"Effect":   "Allow",
			"Action":   actions,
			"Resource": "*",
		}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// simulate runs SimulatePrincipalPolicy over actions (chunked + paginated) and
// returns a decision per action. An error means simulation is unusable (e.g. the
// identity lacks iam:SimulatePrincipalPolicy) and the caller should fall back.
func simulate(ctx context.Context, sim Simulator, principalARN string, actions []string) (map[string]Decision, error) {
	out := make(map[string]Decision, len(actions))
	for start := 0; start < len(actions); start += simBatch {
		end := start + simBatch
		if end > len(actions) {
			end = len(actions)
		}
		batch := actions[start:end]
		var marker *string
		for {
			resp, err := sim.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
				PolicySourceArn: awssdk.String(principalARN),
				ActionNames:     batch,
				Marker:          marker,
			})
			if err != nil {
				return nil, err
			}
			for _, r := range resp.EvaluationResults {
				name := awssdk.ToString(r.EvalActionName)
				if name == "" {
					continue
				}
				if r.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
					out[name] = DecisionAllowed
				} else {
					out[name] = DecisionDenied
				}
			}
			if !resp.IsTruncated || resp.Marker == nil {
				break
			}
			marker = resp.Marker
		}
	}
	return out, nil
}

// unionActions returns the de-duplicated set of all tools' required actions.
func unionActions(tools []Tool) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range tools {
		for _, a := range t.RequiredActions {
			if _, ok := seen[a]; ok {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

func describeMethod(sim, probe bool) string {
	switch {
	case sim && probe:
		return "IAM simulation + live probe"
	case sim:
		return "IAM simulation"
	case probe:
		return "live probe"
	default:
		return "none (no verification source)"
	}
}

func condense(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
