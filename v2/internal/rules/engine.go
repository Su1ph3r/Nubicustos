package rules

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// Evaluate runs every rule against the collected state and returns the findings
// for resources whose expression is true, plus any per-evaluation errors. Rules
// are matched to resources by type, so an expression only sees attributes its
// declared type provides.
//
// A CEL runtime error (e.g. a rule referencing an attribute key that a resource
// instance lacks — typically a typo in a user rule) is returned, never silently
// swallowed: in a security scanner a rule that errors instead of matching is a
// false negative the operator must be told about.
func Evaluate(rs []Rule, st *state.State) ([]findings.Finding, []error) {
	resources := Flatten(st)
	byType := map[string][]Resource{}
	for _, r := range resources {
		byType[r.Type] = append(byType[r.Type], r)
	}

	now := time.Now().UTC()
	var out []findings.Finding
	var errs []error
	for _, rule := range rs {
		if rule.program == nil {
			continue // not compiled (defensive; loaders always compile)
		}
		for _, res := range byType[rule.ResourceType] {
			matched, err := rule.matches(res)
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %q on %s %q: %w", rule.ID, res.Type, res.ID, err))
				continue
			}
			if matched {
				out = append(out, rule.toFinding(res, now))
			}
		}
	}
	return out, errs
}

// matches evaluates the rule's compiled CEL program against a resource's attrs.
func (r *Rule) matches(res Resource) (bool, error) {
	val, _, err := r.program.Eval(map[string]any{"resource": res.Attrs})
	if err != nil {
		return false, err
	}
	b, ok := val.Value().(bool)
	return ok && b, nil
}

func (r *Rule) toFinding(res Resource, now time.Time) findings.Finding {
	return findings.Finding{
		ID:       r.ID + "::" + res.ID,
		CheckID:  r.ID,
		Title:    r.Title,
		Severity: r.Severity,
		Status:   findings.StatusOpen,
		Provider: r.Provider,
		Service:  r.Service,
		Resource: findings.Resource{
			ID: res.ID, Name: res.Name, Type: res.Type, Provider: r.Provider,
			Account: res.Account, Region: res.Region,
		},
		Description: r.Title,
		Rationale:   r.Rationale,
		Impact:      r.Impact,
		Remediation: r.Remediation,
		PoC:         r.PoC,
		Reachable:   findings.ReachUnknown,
		Compliance:  r.Compliance,
		FirstSeen:   now,
		LastSeen:    now,
	}
}
