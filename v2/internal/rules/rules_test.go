package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// compileOne parses+compiles a single-rule YAML doc and returns the rule.
func compileOne(t *testing.T, yamlDoc string) Rule {
	t.Helper()
	env, err := ruleEnv()
	if err != nil {
		t.Fatalf("ruleEnv: %v", err)
	}
	rs, err := compileFile(env, "test.yaml", []byte(yamlDoc))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs))
	}
	return rs[0]
}

func TestBuiltinRulesCompile(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatalf("built-in rules must compile: %v", err)
	}
	if len(rs) < 4 {
		t.Fatalf("expected the built-in rules to load, got %d", len(rs))
	}
}

func TestBuiltinRulesFireOnSample(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	fs, evalErrs := Evaluate(rs, SampleState())
	if len(evalErrs) != 0 {
		t.Fatalf("built-in rules should not produce eval errors on the sample: %v", evalErrs)
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.CheckID] = true
	}
	for _, id := range []string{
		"rule_aws_s3_public_acl_or_policy", "rule_aws_rds_public",
		"rule_azure_storage_blob_public", "rule_k8s_privileged_pod",
	} {
		if !got[id] {
			t.Errorf("expected built-in rule %q to fire on the sample", id)
		}
	}
}

func TestRuleMatchesAndEmitsFinding(t *testing.T) {
	rule := compileOne(t, `
id: r_test
title: public bucket
severity: high
provider: aws
service: s3
resource_type: aws_s3_bucket
expression: 'resource.policy_public && !resource.fully_blocked'
remediation: block it
`)
	st := state.New()
	st.AWS.S3Buckets = []state.S3Bucket{
		{Name: "bad", Region: "us-east-1", PolicyPublic: true},
		{Name: "good", Region: "us-east-1"},
	}
	fs, _ := Evaluate([]Rule{rule}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "bad" {
		t.Fatalf("expected only the public bucket to match, got %+v", fs)
	}
	if fs[0].Severity != findings.SeverityHigh || fs[0].CheckID != "r_test" {
		t.Fatalf("unexpected finding shape: %+v", fs[0])
	}
}

func TestRuleOnlyEvaluatesMatchingType(t *testing.T) {
	// A rule for aws_rds_instance must not be evaluated against s3 buckets (whose
	// attrs lack "public"), proving type-scoping avoids missing-key eval errors.
	rule := compileOne(t, `
id: r_rds
title: public rds
severity: high
provider: aws
service: rds
resource_type: aws_rds_instance
expression: 'resource.public'
`)
	st := state.New()
	st.AWS.S3Buckets = []state.S3Bucket{{Name: "b", PolicyPublic: true}}
	st.AWS.RDSInstances = []state.RDSInstance{{ID: "db", Public: true}}
	fs, _ := Evaluate([]Rule{rule}, st)
	if len(fs) != 1 || fs[0].Resource.ID != "db" {
		t.Fatalf("rule should match only the rds instance, got %+v", fs)
	}
}

func TestEvaluateSurfacesRuntimeError(t *testing.T) {
	// A rule referencing an attribute the resource type does not provide raises a
	// CEL runtime "no such key" error, which must be returned (not silently
	// dropped as a non-match).
	rule := compileOne(t, `
id: r_typo
title: typo'd field
severity: high
provider: aws
service: s3
resource_type: aws_s3_bucket
expression: 'resource.no_such_field'
`)
	st := state.New()
	st.AWS.S3Buckets = []state.S3Bucket{{Name: "b", PolicyPublic: true}}
	fs, errs := Evaluate([]Rule{rule}, st)
	if len(fs) != 0 {
		t.Fatalf("a rule that errors must not emit a finding, got %+v", fs)
	}
	if len(errs) != 1 {
		t.Fatalf("a runtime eval error must be surfaced, got %d errors", len(errs))
	}
}

func TestCheckUniqueIDs(t *testing.T) {
	rs := []Rule{{ID: "a"}, {ID: "b"}, {ID: "a"}}
	if CheckUniqueIDs(rs) == nil {
		t.Fatal("duplicate ids must be reported")
	}
	if CheckUniqueIDs([]Rule{{ID: "a"}, {ID: "b"}}) != nil {
		t.Fatal("unique ids must pass")
	}
}

func TestCheckResourceTypes(t *testing.T) {
	if CheckResourceTypes([]Rule{{ID: "x", ResourceType: "aws_lambda_function"}}) == nil {
		t.Fatal("an unsupported resource_type must be reported")
	}
	if CheckResourceTypes([]Rule{{ID: "x", ResourceType: "aws_s3_bucket"}}) != nil {
		t.Fatal("a supported resource_type must pass")
	}
}

func TestParseRulesEmptyVsMalformed(t *testing.T) {
	if rs, err := parseRules([]byte("   \n")); err != nil || rs != nil {
		t.Fatalf("genuinely empty content is not an error, got %v / %d", err, len(rs))
	}
	// Non-empty content that decodes to a rule with no id is an error, not silent-zero.
	if _, err := parseRules([]byte("titel: typo\nseverity: high\n")); err == nil {
		t.Fatal("a non-empty doc with no id must be an error")
	}
}

func TestLoadDirIsolatesBadFile(t *testing.T) {
	dir := t.TempDir()
	good := "id: good_rule\ntitle: t\nseverity: low\nprovider: aws\nservice: s3\nresource_type: aws_s3_bucket\nexpression: 'resource.policy_public'\n"
	bad := "this: is\n  not: a valid rule\n" // no id -> parse error
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadDir(dir)
	if err == nil {
		t.Fatal("the bad file should be reported")
	}
	if len(rs) != 1 || rs[0].ID != "good_rule" {
		t.Fatalf("the good rule must still load despite the bad file, got %+v", rs)
	}
}

func TestCompileRejectsConcreteNonBoolExpression(t *testing.T) {
	// A concretely-typed non-bool expression (here an int literal) is rejected.
	// A bare dyn attribute access (resource.name) cannot be distinguished from a
	// bool field at compile time over a dyn map, so it is accepted and simply
	// never matches at runtime — that is the documented trade-off.
	env, _ := ruleEnv()
	_, err := compileFile(env, "x.yaml", []byte(`
id: bad
title: t
severity: low
resource_type: aws_s3_bucket
expression: '42'
`))
	if err == nil {
		t.Fatal("a concretely-typed non-bool expression must be rejected")
	}
}

func TestCompileRejectsBadCEL(t *testing.T) {
	env, _ := ruleEnv()
	_, err := compileFile(env, "x.yaml", []byte(`
id: bad
title: t
severity: low
resource_type: aws_s3_bucket
expression: 'resource.name ==='
`))
	if err == nil {
		t.Fatal("a syntactically invalid CEL expression must be rejected")
	}
}

func TestCompileRejectsMissingFields(t *testing.T) {
	env, _ := ruleEnv()
	_, err := compileFile(env, "x.yaml", []byte(`
id: bad
title: t
resource_type: aws_s3_bucket
expression: 'resource.policy_public'
`))
	if err == nil {
		t.Fatal("a rule missing severity must be rejected")
	}
}

func TestFlattenCoversProviders(t *testing.T) {
	st := SampleState()
	types := map[string]bool{}
	for _, r := range Flatten(st) {
		types[r.Type] = true
		if r.Attrs["type"] != r.Type {
			t.Fatalf("attrs missing type key for %s", r.Type)
		}
	}
	for _, want := range []string{"aws_s3_bucket", "aws_rds_instance", "azure_storage_account", "k8s_pod"} {
		if !types[want] {
			t.Errorf("Flatten missing type %q", want)
		}
	}
}
