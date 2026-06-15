// Package rules is the policy-as-code engine (plan §9.6): declarative YAML rules
// whose CEL expression is evaluated against the collected cloud state, loaded at
// runtime so a finding can be encoded without recompiling. Built-in rules and
// user-supplied rules share this one engine.
package rules

import (
	"bytes"
	"fmt"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// Rule is a declarative check. The CEL Expression is evaluated against each
// collected resource whose type equals ResourceType; when it returns true a
// finding is emitted. Restricting evaluation to the declared type means the
// expression only ever sees attributes that type actually has.
type Rule struct {
	ID           string                   `yaml:"id"`
	Title        string                   `yaml:"title"`
	Severity     findings.Severity        `yaml:"severity"`
	Provider     string                   `yaml:"provider"`
	Service      string                   `yaml:"service"`
	ResourceType string                   `yaml:"resource_type"`
	Expression   string                   `yaml:"expression"`
	Rationale    string                   `yaml:"rationale"`
	Impact       string                   `yaml:"impact"`
	Remediation  string                   `yaml:"remediation"`
	PoC          string                   `yaml:"poc"`
	Compliance   []findings.ComplianceRef `yaml:"compliance"`

	program cel.Program // compiled expression
}

// ruleEnv is the CEL environment: a single `resource` variable holding the
// resource's attribute map. Built once and shared across rule compilation.
func ruleEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// compile validates a rule's metadata and compiles its CEL expression. The
// returned error names the rule so a bad rule file is actionable.
func (r *Rule) compile(env *cel.Env) error {
	if r.ID == "" || r.Title == "" || r.ResourceType == "" || r.Expression == "" {
		return fmt.Errorf("rule %q: id, title, resource_type, and expression are required", r.ID)
	}
	if r.Severity == "" {
		return fmt.Errorf("rule %q: severity is required", r.ID)
	}
	ast, issues := env.Compile(r.Expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("rule %q: compiling expression: %w", r.ID, issues.Err())
	}
	// The expression must yield a boolean. Attribute access over the dyn-typed
	// resource map types as "dyn" (resolved at runtime), which is allowed; the
	// runtime evaluator asserts the result is actually bool. A concretely-typed
	// non-bool expression (a string/int literal or comparison) is rejected here.
	if ot := ast.OutputType().String(); ot != "bool" && ot != "dyn" {
		return fmt.Errorf("rule %q: expression must evaluate to bool, got %s", r.ID, ot)
	}
	prg, err := env.Program(ast)
	if err != nil {
		return fmt.Errorf("rule %q: building program: %w", r.ID, err)
	}
	r.program = prg
	return nil
}

// parseRules decodes a YAML document that is either a single rule or a list.
// A non-empty document that decodes to a rule with no id is treated as an error
// (rather than silently yielding zero rules), so a wrong top-level key or a
// mistyped field surfaces instead of disabling the rule unnoticed.
func parseRules(data []byte) ([]Rule, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil // genuinely empty file
	}
	var list []Rule
	if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return list, nil
	}
	var one Rule
	if err := yaml.Unmarshal(data, &one); err != nil {
		return nil, err
	}
	if one.ID == "" {
		return nil, fmt.Errorf("no valid rule found (missing 'id' — check the top-level keys and indentation)")
	}
	return []Rule{one}, nil
}
