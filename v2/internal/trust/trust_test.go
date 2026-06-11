package trust

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

const thisAccount = "111122223333"

// awsWith returns AWS state with collected IAM containing the given roles/users.
func awsWith(users []state.IAMUser, roles []state.IAMRole) *state.AWS {
	return &state.AWS{Account: thisAccount, IAM: state.IAMState{Collected: true, Users: users, Roles: roles}}
}

func allow(actions, resources []string) state.PolicyDocument {
	return state.PolicyDocument{Statements: []state.PolicyStatement{{Effect: "Allow", Actions: actions, Resources: resources}}}
}

func trustStmt(s state.PolicyStatement) state.PolicyDocument {
	return state.PolicyDocument{Statements: []state.PolicyStatement{s}}
}

func TestExternalAccountTrust(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "cross", ARN: "arn:aws:iam::111122223333:role/cross",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{"arn:aws:iam::999988887777:root"}}),
	}}
	rep := Analyze(awsWith(nil, roles))

	var ext *AssumeRelation
	for i := range rep.Assumes {
		if rep.Assumes[i].Source == SourceExternal {
			ext = &rep.Assumes[i]
		}
	}
	if ext == nil || !ext.Risky {
		t.Fatalf("expected a risky external assume relation, got %+v", rep.Assumes)
	}
	if !hasFindingCheck(rep, "aws_iam_role_trust_external_account") {
		t.Fatalf("expected external-account finding, got %v", checkIDs(rep))
	}
}

func TestSameAccountTrustIsIntraNotExternal(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "internal", ARN: "arn:aws:iam::111122223333:role/internal",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{"arn:aws:iam::111122223333:role/app"}}),
	}}
	rep := Analyze(awsWith(nil, roles))
	if len(rep.Assumes) != 1 || rep.Assumes[0].Source != SourceIntraAccount || rep.Assumes[0].Risky {
		t.Fatalf("expected one non-risky intra-account relation, got %+v", rep.Assumes)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("intra-account trust should produce no findings, got %v", checkIDs(rep))
	}
}

func TestWildcardPrincipalTrustIsCritical(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "open", ARN: "arn:aws:iam::111122223333:role/open",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{"*"}}),
	}}
	rep := Analyze(awsWith(nil, roles))
	f := findingByCheck(rep, "aws_iam_role_trust_wildcard_principal")
	if f == nil || f.Severity != findings.SeverityCritical {
		t.Fatalf("expected critical wildcard finding, got %v", checkIDs(rep))
	}
}

func TestOIDCTrustWithoutSubjectIsRisky(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "gha", ARN: "arn:aws:iam::111122223333:role/gha",
		TrustPolicy: trustStmt(state.PolicyStatement{
			Effect:    "Allow",
			Federated: []string{"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
			// no sub/aud condition
		}),
	}}
	rep := Analyze(awsWith(nil, roles))
	if !hasFindingCheck(rep, "aws_iam_oidc_trust_no_subject_condition") {
		t.Fatalf("expected OIDC no-subject finding, got %v", checkIDs(rep))
	}
}

func TestOIDCTrustWithSubjectConditionIsNotFlagged(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "gha", ARN: "arn:aws:iam::111122223333:role/gha",
		TrustPolicy: trustStmt(state.PolicyStatement{
			Effect:        "Allow",
			Federated:     []string{"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
			ConditionKeys: []string{"token.actions.githubusercontent.com:sub"},
		}),
	}}
	rep := Analyze(awsWith(nil, roles))
	if hasFindingCheck(rep, "aws_iam_oidc_trust_no_subject_condition") {
		t.Fatalf("OIDC with a subject condition must not be flagged, got %v", checkIDs(rep))
	}
	if len(rep.Assumes) != 1 || rep.Assumes[0].Risky {
		t.Fatalf("expected a non-risky OIDC relation, got %+v", rep.Assumes)
	}
}

func TestPrivescDetection(t *testing.T) {
	users := []state.IAMUser{{Name: "deployer", Policies: []state.PolicyDocument{
		allow([]string{"iam:PutUserPolicy", "s3:GetObject"}, []string{"*"}),
	}}}
	rep := Analyze(awsWith(users, nil))
	if len(rep.Privs) != 1 || len(rep.Privs[0].Privesc) != 1 || rep.Privs[0].Privesc[0] != "iam:putuserpolicy" {
		t.Fatalf("expected privesc on iam:putuserpolicy, got %+v", rep.Privs)
	}
	if !hasFindingCheck(rep, "aws_iam_privilege_escalation") {
		t.Fatalf("expected privilege-escalation finding, got %v", checkIDs(rep))
	}
}

func TestPrivescRequiresBroadResource(t *testing.T) {
	users := []state.IAMUser{{Name: "scoped", Policies: []state.PolicyDocument{
		allow([]string{"iam:PutUserPolicy"}, []string{"arn:aws:iam::111122223333:user/scoped"}),
	}}}
	rep := Analyze(awsWith(users, nil))
	if len(rep.Privs) != 0 {
		t.Fatalf("privesc action scoped to a specific resource must not flag, got %+v", rep.Privs)
	}
}

func TestBareAccountIDExternalTrust(t *testing.T) {
	// Principal as the bare 12-digit account-id shorthand must still be detected
	// as external — missing this is a security-relevant false negative.
	roles := []state.IAMRole{{
		Name: "shorthand", ARN: "arn:aws:iam::111122223333:role/shorthand",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{"999988887777"}}),
	}}
	rep := Analyze(awsWith(nil, roles))
	if !hasFindingCheck(rep, "aws_iam_role_trust_external_account") {
		t.Fatalf("bare account-id principal should be flagged external, got %v", checkIDs(rep))
	}
}

func TestBareAccountIDSameAccountIsIntra(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "self", ARN: "arn:aws:iam::111122223333:role/self",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{thisAccount}}),
	}}
	rep := Analyze(awsWith(nil, roles))
	if len(rep.Assumes) != 1 || rep.Assumes[0].Source != SourceIntraAccount {
		t.Fatalf("same bare account-id should be intra-account, got %+v", rep.Assumes)
	}
}

func TestEmptyScanAccountFailsSafeToExternal(t *testing.T) {
	// When the scan account is unknown, an account-bearing principal must be
	// treated as external (fail safe), not silently assumed intra-account.
	a := &state.AWS{Account: "", IAM: state.IAMState{Collected: true, Roles: []state.IAMRole{{
		Name: "r", ARN: "arn:aws:iam::111122223333:role/r",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{"arn:aws:iam::555566667777:root"}}),
	}}}}
	rep := Analyze(a)
	if !hasFindingCheck(rep, "aws_iam_role_trust_external_account") {
		t.Fatalf("unknown scan account should fail safe to external, got %v", checkIDs(rep))
	}
}

func TestEmptyPrincipalProducesNoRelation(t *testing.T) {
	roles := []state.IAMRole{{
		Name: "r", ARN: "arn:aws:iam::111122223333:role/r",
		TrustPolicy: trustStmt(state.PolicyStatement{Effect: "Allow", AWSPrincipals: []string{""}}),
	}}
	rep := Analyze(awsWith(nil, roles))
	if len(rep.Assumes) != 0 {
		t.Fatalf("empty principal must not synthesize a relation, got %+v", rep.Assumes)
	}
}

func TestServiceWildcardActionMatchesPrivesc(t *testing.T) {
	users := []state.IAMUser{{Name: "iamadmin", Policies: []state.PolicyDocument{
		allow([]string{"iam:*"}, []string{"*"}),
	}}}
	rep := Analyze(awsWith(users, nil))
	if len(rep.Privs) != 1 || len(rep.Privs[0].Privesc) == 0 {
		t.Fatalf("iam:* should match privesc actions, got %+v", rep.Privs)
	}
}

func TestAdminViaCustomPolicyEmitsFinding(t *testing.T) {
	users := []state.IAMUser{{Name: "godmode", Policies: []state.PolicyDocument{
		allow([]string{"*"}, []string{"*"}),
	}}}
	rep := Analyze(awsWith(users, nil))
	if len(rep.Privs) != 1 || !rep.Privs[0].Admin || !rep.Privs[0].AdminViaPolicy {
		t.Fatalf("expected admin-via-policy, got %+v", rep.Privs)
	}
	if !hasFindingCheck(rep, "aws_iam_admin_via_policy") {
		t.Fatalf("expected admin-via-policy finding, got %v", checkIDs(rep))
	}
}

func TestAttachedAdminDoesNotDuplicateFinding(t *testing.T) {
	// AdministratorAccess attached (no wildcard custom policy): admin for the
	// graph, but no aws_iam_admin_via_policy finding (the user-admin check owns it).
	users := []state.IAMUser{{Name: "boss", AdminAttached: true}}
	rep := Analyze(awsWith(users, nil))
	if len(rep.Privs) != 1 || !rep.Privs[0].Admin || rep.Privs[0].AdminViaPolicy {
		t.Fatalf("expected admin (attached, not via policy), got %+v", rep.Privs)
	}
	if hasFindingCheck(rep, "aws_iam_admin_via_policy") {
		t.Fatalf("attached admin must not duplicate the via-policy finding, got %v", checkIDs(rep))
	}
}

func TestAnalyzeNilAndUncollected(t *testing.T) {
	if rep := Analyze(nil); len(rep.Findings) != 0 || len(rep.Privs) != 0 {
		t.Fatal("nil state should yield empty report")
	}
	if rep := Analyze(&state.AWS{}); len(rep.Findings) != 0 {
		t.Fatal("uncollected IAM should yield empty report")
	}
}

// --- helpers ---------------------------------------------------------------

func hasFindingCheck(rep Report, checkID string) bool { return findingByCheck(rep, checkID) != nil }

func findingByCheck(rep Report, checkID string) *findings.Finding {
	for i := range rep.Findings {
		if rep.Findings[i].CheckID == checkID {
			return &rep.Findings[i]
		}
	}
	return nil
}

func checkIDs(rep Report) string {
	var ids []string
	for _, f := range rep.Findings {
		ids = append(ids, f.CheckID)
	}
	return strings.Join(ids, ",")
}
