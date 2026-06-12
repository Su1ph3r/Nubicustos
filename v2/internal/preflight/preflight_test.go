package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeSim returns canned decisions per action, or an error to model an identity
// that lacks iam:SimulatePrincipalPolicy.
type fakeSim struct {
	allow map[string]bool
	err   error
	calls int
}

func (f *fakeSim) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := &iam.SimulatePrincipalPolicyOutput{}
	for _, a := range in.ActionNames {
		dec := iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		if f.allow[a] {
			dec = iamtypes.PolicyEvaluationDecisionTypeAllowed
		}
		out.EvaluationResults = append(out.EvaluationResults, iamtypes.EvaluationResult{
			EvalActionName: awssdk.String(a),
			EvalDecision:   dec,
		})
	}
	return out, nil
}

// fakeProbe returns canned decisions per action; absent actions are unknown.
type fakeProbe struct{ d map[string]Decision }

func (f fakeProbe) Probe(_ context.Context, action string) Decision {
	if v, ok := f.d[action]; ok {
		return v
	}
	return DecisionUnknown
}

func twoActionTool() Tool {
	return Tool{
		Key: "t", Name: "T", RemediationPolicyName: "TPolicy",
		RequiredManagedPolicies: []string{"SecurityAudit"},
		RequiredActions:         []string{"s3:GetBucketAcl", "iam:ListUsers"},
	}
}

func toolReport(r Report) ToolReport { return r.Tools[0] }

func TestEvaluateAllAllowedIsReady(t *testing.T) {
	sim := &fakeSim{allow: map[string]bool{"s3:GetBucketAcl": true, "iam:ListUsers": true}}
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn:aws:iam::1:user/a", Tools: []Tool{twoActionTool()}, Simulator: sim,
	})
	tr := toolReport(rep)
	if tr.Readiness != ReadinessReady {
		t.Fatalf("all-allowed should be ready, got %s", tr.Readiness)
	}
	if rep.Overall != ReadinessReady {
		t.Fatalf("overall should be ready, got %s", rep.Overall)
	}
	if len(tr.Denied) != 0 || tr.Remediate.PolicyDocument != "" {
		t.Fatalf("a ready tool needs no remediation policy, got %+v", tr.Remediate)
	}
	if !strings.Contains(tr.Remediate.Summary, "ready") {
		t.Fatalf("summary should say ready: %q", tr.Remediate.Summary)
	}
}

func TestEvaluatePartialEmitsExactMissingAndPolicy(t *testing.T) {
	sim := &fakeSim{allow: map[string]bool{"s3:GetBucketAcl": true}} // iam:ListUsers denied
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn:aws:iam::1:user/a", Tools: []Tool{twoActionTool()}, Simulator: sim,
	})
	tr := toolReport(rep)
	if tr.Readiness != ReadinessPartial {
		t.Fatalf("one-missing should be partial, got %s", tr.Readiness)
	}
	if len(tr.Denied) != 1 || tr.Denied[0] != "iam:ListUsers" {
		t.Fatalf("denied should be exactly [iam:ListUsers], got %v", tr.Denied)
	}
	// The generated remediation policy must contain exactly the missing action.
	if !strings.Contains(tr.Remediate.PolicyDocument, "iam:ListUsers") {
		t.Fatalf("remediation policy should grant the missing action:\n%s", tr.Remediate.PolicyDocument)
	}
	if strings.Contains(tr.Remediate.PolicyDocument, "s3:GetBucketAcl") {
		t.Fatalf("remediation policy must NOT include already-allowed actions:\n%s", tr.Remediate.PolicyDocument)
	}
	if !strings.Contains(tr.Remediate.Summary, "SecurityAudit") {
		t.Fatalf("summary should name the managed policy: %q", tr.Remediate.Summary)
	}
}

func TestEvaluateAllDeniedIsFailed(t *testing.T) {
	sim := &fakeSim{allow: map[string]bool{}}
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn", Tools: []Tool{twoActionTool()}, Simulator: sim,
	})
	if toolReport(rep).Readiness != ReadinessFailed {
		t.Fatalf("all-denied should be failed, got %s", toolReport(rep).Readiness)
	}
}

func TestConflictBetweenSimulateAndProbeIsDeniedAndFlagged(t *testing.T) {
	// Simulation allows iam:ListUsers, but the live probe denies it (SCP).
	sim := &fakeSim{allow: map[string]bool{"s3:GetBucketAcl": true, "iam:ListUsers": true}}
	probe := fakeProbe{d: map[string]Decision{"iam:ListUsers": DecisionDenied, "s3:GetBucketAcl": DecisionAllowed}}
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn", Tools: []Tool{twoActionTool()}, Simulator: sim, Prober: probe,
	})
	tr := toolReport(rep)
	if len(tr.Conflicts) != 1 || tr.Conflicts[0] != "iam:ListUsers" {
		t.Fatalf("the SCP-blocked action should be flagged as a conflict, got %v", tr.Conflicts)
	}
	// A conflict is treated as denied (runtime wins).
	found := false
	for _, a := range tr.Actions {
		if a.Action == "iam:ListUsers" {
			found = true
			if a.Decision != DecisionDenied || !a.Conflict {
				t.Fatalf("conflict action should be denied+conflict, got %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("iam:ListUsers action result missing")
	}
	if !strings.Contains(tr.Remediate.Summary, "runtime") {
		t.Fatalf("summary should mention the runtime/SCP block: %q", tr.Remediate.Summary)
	}
}

func TestConflictExcludedFromRemediationPolicy(t *testing.T) {
	// s3:GetBucketAcl is genuinely IAM-denied; iam:ListUsers is IAM-allowed but
	// runtime-blocked (conflict). The generated grant must include only the real
	// IAM gap — attaching a policy cannot fix an SCP block.
	sim := &fakeSim{allow: map[string]bool{"iam:ListUsers": true}} // s3 denied
	probe := fakeProbe{d: map[string]Decision{"iam:ListUsers": DecisionDenied, "s3:GetBucketAcl": DecisionDenied}}
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn", Tools: []Tool{twoActionTool()}, Simulator: sim, Prober: probe,
	})
	tr := toolReport(rep)
	if len(tr.Conflicts) != 1 || tr.Conflicts[0] != "iam:ListUsers" {
		t.Fatalf("iam:ListUsers should be the conflict, got %v", tr.Conflicts)
	}
	if !strings.Contains(tr.Remediate.PolicyDocument, "s3:GetBucketAcl") {
		t.Fatalf("the genuinely IAM-missing action should be in the policy:\n%s", tr.Remediate.PolicyDocument)
	}
	if strings.Contains(tr.Remediate.PolicyDocument, "iam:ListUsers") {
		t.Fatalf("a runtime-blocked (SCP) action must NOT be in the grant — a policy can't fix it:\n%s", tr.Remediate.PolicyDocument)
	}
	if !strings.Contains(tr.Remediate.Summary, "SCP") {
		t.Fatalf("summary should call out the runtime/SCP block separately: %q", tr.Remediate.Summary)
	}
}

func TestSimulationUnavailableFallsBackToProbe(t *testing.T) {
	sim := &fakeSim{err: errors.New("AccessDenied: not authorized to perform iam:SimulatePrincipalPolicy")}
	probe := fakeProbe{d: map[string]Decision{"s3:GetBucketAcl": DecisionAllowed, "iam:ListUsers": DecisionDenied}}
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn", Tools: []Tool{twoActionTool()}, Simulator: sim, Prober: probe,
	})
	if !strings.Contains(rep.Method, "simulation unavailable") {
		t.Fatalf("method should note simulation was unavailable: %q", rep.Method)
	}
	tr := toolReport(rep)
	if tr.Readiness != ReadinessPartial {
		t.Fatalf("probe-only should still classify, got %s", tr.Readiness)
	}
	for _, a := range tr.Actions {
		if a.Basis != BasisProbed {
			t.Fatalf("with simulation down, decisions must come from the probe, got %s for %s", a.Basis, a.Action)
		}
	}
}

func TestUnverifiedActionsDoNotPassAsReady(t *testing.T) {
	// Simulation off; the probe knows only one of two required actions → the
	// other is unverified. An unverified action must NOT be absorbed into a
	// "ready" verdict (that would certify access the check never confirmed).
	probe := fakeProbe{d: map[string]Decision{"s3:GetBucketAcl": DecisionAllowed}}
	rep := Evaluate(context.Background(), Options{
		Provider: "aws", Identity: "arn", Tools: []Tool{twoActionTool()}, Prober: probe,
	})
	tr := toolReport(rep)
	if len(tr.Unknown) != 1 || tr.Unknown[0] != "iam:ListUsers" {
		t.Fatalf("the unprobed action should be unknown, got %v", tr.Unknown)
	}
	if tr.Readiness != ReadinessUnverified {
		t.Fatalf("an unverified action must yield 'unverified', not 'ready', got %s", tr.Readiness)
	}
	if rep.Overall == ReadinessReady {
		t.Fatal("overall must not be ready when a tool is unverified (so the CLI gate fails)")
	}
	if !strings.Contains(tr.Remediate.Summary, "could not be verified") {
		t.Fatalf("remediation should flag the unverified permission: %q", tr.Remediate.Summary)
	}
}

func TestNoVerificationSourceIsUnverified(t *testing.T) {
	rep := Evaluate(context.Background(), Options{Provider: "aws", Identity: "arn", Tools: []Tool{twoActionTool()}})
	if rep.Overall != ReadinessUnverified {
		t.Fatalf("no simulator and no prober should yield unverified (not ready), got %s", rep.Overall)
	}
	if !strings.Contains(rep.Method, "no verification source") {
		t.Fatalf("method should note there was no source: %q", rep.Method)
	}
}

func TestSimulationChunksLargeActionSets(t *testing.T) {
	// More actions than one batch forces multiple simulate calls.
	actions := make([]string, simBatch+5)
	allow := map[string]bool{}
	for i := range actions {
		actions[i] = "svc:Action" + string(rune('A'+i%26)) + itoa(i)
		allow[actions[i]] = true
	}
	sim := &fakeSim{allow: allow}
	tool := Tool{Key: "big", Name: "Big", RequiredActions: actions, RemediationPolicyName: "P"}
	rep := Evaluate(context.Background(), Options{Provider: "aws", Identity: "arn", Tools: []Tool{tool}, Simulator: sim})
	if sim.calls < 2 {
		t.Fatalf("a >batch action set should chunk into multiple calls, got %d", sim.calls)
	}
	if toolReport(rep).Readiness != ReadinessReady {
		t.Fatalf("all-allowed large set should be ready, got %s", toolReport(rep).Readiness)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestCatalogNativeAndExternalPresent(t *testing.T) {
	if _, ok := AWSToolByKey("nubicustos"); !ok {
		t.Fatal("native nubicustos tool must be in the catalog")
	}
	for _, k := range []string{"prowler", "scoutsuite", "cloudsploit"} {
		if _, ok := AWSToolByKey(k); !ok {
			t.Fatalf("external tool %q must be in the catalog", k)
		}
	}
	// Native action list should be non-trivial and well-formed (service:Action).
	nub, _ := AWSToolByKey("nubicustos")
	if len(nub.RequiredActions) < 20 {
		t.Fatalf("native action list looks too small: %d", len(nub.RequiredActions))
	}
	for _, a := range nub.RequiredActions {
		if !strings.Contains(a, ":") {
			t.Fatalf("malformed action %q", a)
		}
	}
}
