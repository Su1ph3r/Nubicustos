package aws

import (
	"encoding/json"
	"net/url"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

// parsePolicyDocument decodes a URL-encoded IAM policy document (permission or
// trust) into the normalized state.PolicyDocument. IAM fields are polymorphic
// (a value may be a single string or an array; Statement may be one object or a
// list), so every field is decoded through stringOrSlice. A decode failure
// yields an empty document rather than an error — a single malformed policy must
// not blank the whole scan.
//
// Scope: the Action, Resource, Principal, and Condition-key shapes are parsed.
// The negated forms NotAction/NotResource/NotPrincipal are intentionally NOT
// parsed; downstream analyzers evaluate only the positive Allow forms, so a
// grant expressed solely via a Not* element is not surfaced. This is a known
// analysis-depth limitation, documented rather than partially (and incorrectly)
// implemented.
func parsePolicyDocument(encoded string) state.PolicyDocument {
	if encoded == "" {
		return state.PolicyDocument{}
	}
	decoded := encoded
	if u, err := url.PathUnescape(encoded); err == nil {
		decoded = u // PathUnescape preserves '+' (legal in base64 condition values)
	}

	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &raw); err != nil {
		return state.PolicyDocument{}
	}

	stmts := statementsFromRaw(raw.Statement)
	doc := state.PolicyDocument{}
	for _, s := range stmts {
		doc.Statements = append(doc.Statements, normalizeStatement(s))
	}
	return doc
}

// rawStatement mirrors a single IAM statement with polymorphic fields kept raw.
type rawStatement struct {
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

// statementsFromRaw handles Statement being either one object or an array.
func statementsFromRaw(raw json.RawMessage) []rawStatement {
	if len(raw) == 0 {
		return nil
	}
	var list []rawStatement
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one rawStatement
	if err := json.Unmarshal(raw, &one); err == nil {
		return []rawStatement{one}
	}
	return nil
}

func normalizeStatement(s rawStatement) state.PolicyStatement {
	out := state.PolicyStatement{
		Effect:    s.Effect,
		Actions:   stringOrSlice(s.Action),
		Resources: stringOrSlice(s.Resource),
	}
	out.AWSPrincipals, out.Federated, out.Services = parsePrincipal(s.Principal)
	out.ConditionKeys = conditionKeys(s.Condition)
	return out
}

// stringOrSlice decodes a JSON value that may be a string or an array of strings.
func stringOrSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	return nil
}

// parsePrincipal decodes the Principal block, which may be the string "*" or an
// object with AWS / Federated / Service keys (each a string or array).
func parsePrincipal(raw json.RawMessage) (aws, federated, services []string) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	// Principal: "*"
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		return []string{star}, nil, nil
	}
	var obj struct {
		AWS       json.RawMessage `json:"AWS"`
		Federated json.RawMessage `json:"Federated"`
		Service   json.RawMessage `json:"Service"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, nil, nil
	}
	return stringOrSlice(obj.AWS), stringOrSlice(obj.Federated), stringOrSlice(obj.Service)
}

// conditionKeys flattens the condition block to the set of condition keys it
// references (e.g. "token.actions.githubusercontent.com:sub"). The presence or
// absence of a sub/aud key is what the OIDC trust analysis needs; the values
// themselves are not required.
func conditionKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var byOperator map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byOperator); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var keys []string
	for _, kv := range byOperator {
		for k := range kv {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	return keys
}
