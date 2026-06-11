// Package rules registers the policy-as-code engine as a check so its findings
// flow through the normal scan pipeline. It evaluates the embedded built-in
// rules plus any user-supplied rules directory (set via SetUserRulesDir).
package rules

import (
	"errors"
	"sync"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/rules"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(rulesCheck{}) }

var (
	mu           sync.Mutex
	userRulesDir string
)

// SetUserRulesDir configures the directory of user-supplied rules to load in
// addition to the built-ins. Empty means built-ins only.
func SetUserRulesDir(dir string) {
	mu.Lock()
	defer mu.Unlock()
	userRulesDir = dir
}

func dir() string {
	mu.Lock()
	defer mu.Unlock()
	return userRulesDir
}

// rulesCheck is the umbrella check; each emitted finding carries its rule's id
// as the CheckID. This Spec is the catalog entry for the engine.
type rulesCheck struct{}

func (rulesCheck) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:          "policy_as_code_rules",
		Title:       "Policy-as-code rule evaluation",
		Provider:    "multi",
		Service:     "rules",
		Severity:    findings.SeverityMedium,
		Rationale:   "Declarative CEL/YAML rules encode posture checks that can be added without recompiling.",
		Impact:      "Each matched rule represents a misconfiguration the operator chose to enforce.",
		Remediation: "See the matched rule's own remediation guidance.",
	}
}

func (rulesCheck) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	rs, err := rules.Builtin()
	if err != nil {
		return nil, err // embedded rules must always compile
	}
	// User rules are best-effort: a load/compile failure is surfaced, but the
	// built-in rules (and the other valid user rules) still evaluate so one bad
	// user file doesn't blank the rest.
	user, uerr := rules.LoadDir(dir())
	rs = append(rs, user...)

	var problems []error
	if uerr != nil {
		problems = append(problems, uerr)
	}
	// Surface authoring mistakes that would otherwise silently never fire.
	if e := rules.CheckUniqueIDs(rs); e != nil {
		problems = append(problems, e)
	}
	if e := rules.CheckResourceTypes(user); e != nil {
		problems = append(problems, e)
	}

	fs, evalErrs := rules.Evaluate(rs, st)
	problems = append(problems, evalErrs...)
	return fs, errors.Join(problems...)
}
