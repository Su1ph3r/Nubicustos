// Package trust analyzes IAM trust relationships and permission policies — the
// dimension where modern critical-severity cloud findings actually live (plan
// §9.3). It classifies who may assume each role (intra-account, external
// account, OIDC/SAML federation, or an unconstrained wildcard) and detects
// principals that hold administrative access or hold privilege-escalation-prone
// permissions.
//
// Analyze is pure: it reads collected state and returns both the structured
// relationships the attack-path graph turns into edges and the standalone
// findings the scan pipeline reports.
package trust

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// SourceKind classifies the origin of an assume-role relationship.
type SourceKind string

const (
	SourceIntraAccount SourceKind = "intra-account" // a principal in this account
	SourceExternal     SourceKind = "external"      // a principal in another account
	SourceOIDC         SourceKind = "oidc"          // a federated OIDC provider
	SourceSAML         SourceKind = "saml"          // a federated SAML provider
	SourceWildcard     SourceKind = "wildcard"      // Principal "*"
)

// AssumeRelation is one "X may assume role R" fact derived from a trust policy.
type AssumeRelation struct {
	RoleName  string
	RoleARN   string
	Source    SourceKind
	Principal string // the principal ARN / provider ARN / "*"
	Risky     bool   // external, wildcard, or OIDC without a subject condition
	Reason    string
}

// Privilege records that a principal holds admin or privilege-escalation perms.
type Privilege struct {
	Kind           string // "user" | "role"
	Name           string
	Admin          bool     // admin-equivalent (attached AdministratorAccess or a wildcard policy)
	AdminViaPolicy bool     // admin granted by a custom/inline wildcard (not the managed policy)
	Privesc        []string // matched privilege-escalation actions (empty if none)
}

// Report is the result of analysis.
type Report struct {
	Assumes  []AssumeRelation
	Privs    []Privilege
	Findings []findings.Finding
}

// privescActions is the curated set of IAM/STS actions that let a principal
// grant itself more access. Matched against Allow statements scoped to "*".
var privescActions = map[string]struct{}{
	"iam:createpolicyversion":     {},
	"iam:setdefaultpolicyversion": {},
	"iam:attachuserpolicy":        {},
	"iam:attachrolepolicy":        {},
	"iam:attachgrouppolicy":       {},
	"iam:putuserpolicy":           {},
	"iam:putrolepolicy":           {},
	"iam:putgrouppolicy":          {},
	"iam:createaccesskey":         {},
	"iam:createloginprofile":      {},
	"iam:updateloginprofile":      {},
	"iam:updateassumerolepolicy":  {},
	"iam:addusertogroup":          {},
	"iam:passrole":                {},
	"sts:assumerole":              {},
}

// Analyze inspects the collected IAM state and returns relationships, privilege
// facts, and findings. account is this scan's account id (used to tell intra-
// account principals apart from external ones).
func Analyze(a *state.AWS) Report {
	var rep Report
	if a == nil || !a.IAM.Collected {
		return rep
	}
	account := a.Account
	now := time.Now().UTC()

	for _, u := range a.IAM.Users {
		if p := analyzePermissions("user", u.Name, u.AdminAttached, u.Policies); p.Admin || len(p.Privesc) > 0 {
			rep.Privs = append(rep.Privs, p)
			rep.Findings = append(rep.Findings, privilegeFindings(p, now)...)
		}
	}

	for _, r := range a.IAM.Roles {
		if p := analyzePermissions("role", r.Name, r.AdminAttached, r.Policies); p.Admin || len(p.Privesc) > 0 {
			rep.Privs = append(rep.Privs, p)
			rep.Findings = append(rep.Findings, privilegeFindings(p, now)...)
		}
		rels, fs := analyzeTrust(r, account, now)
		rep.Assumes = append(rep.Assumes, rels...)
		rep.Findings = append(rep.Findings, fs...)
	}
	return rep
}

// analyzePermissions decides whether a principal is admin-equivalent or holds
// privilege-escalation actions, considering both attached AdministratorAccess
// and the contents of its permission policies.
//
// Scope (deliberate, conservative): only Allow statements scoped to Resource
// "*" are evaluated. Deny statements and negated forms (NotAction/NotResource)
// are NOT evaluated — so a wildcard grant neutralized by a Deny is over-reported
// (a false positive, the safe direction for a scanner), and an admin grant
// expressed via NotAction is not detected. Full Deny/Not* evaluation is a
// separate, larger piece of policy-simulation work.
func analyzePermissions(kind, name string, adminAttached bool, docs []state.PolicyDocument) Privilege {
	p := Privilege{Kind: kind, Name: name, Admin: adminAttached}
	seen := map[string]struct{}{}
	for _, doc := range docs {
		for _, st := range doc.Statements {
			if !strings.EqualFold(st.Effect, "Allow") || !broadResource(st.Resources) {
				continue
			}
			if grantsAllActions(st.Actions) {
				p.Admin = true
				p.AdminViaPolicy = true
			}
			for _, act := range st.Actions {
				if matchesPrivesc(act) {
					la := strings.ToLower(act)
					if _, ok := seen[la]; !ok {
						seen[la] = struct{}{}
						p.Privesc = append(p.Privesc, la)
					}
				}
			}
		}
	}
	return p
}

// broadResource reports whether a statement's resource list includes "*".
func broadResource(resources []string) bool {
	for _, r := range resources {
		if r == "*" {
			return true
		}
	}
	return false
}

// grantsAllActions reports whether the action list grants everything ("*").
func grantsAllActions(actions []string) bool {
	for _, a := range actions {
		if a == "*" || a == "*:*" {
			return true
		}
	}
	return false
}

// matchesPrivesc reports whether an action (possibly a wildcard like "iam:*")
// covers any curated privilege-escalation action.
func matchesPrivesc(action string) bool {
	a := strings.ToLower(action)
	if a == "*" || a == "*:*" {
		return true
	}
	if _, ok := privescActions[a]; ok {
		return true
	}
	// Service wildcard, e.g. "iam:*" — covers every privesc action in that service.
	if strings.HasSuffix(a, ":*") {
		svc := strings.TrimSuffix(a, ":*")
		for pa := range privescActions {
			if strings.HasPrefix(pa, svc+":") {
				return true
			}
		}
	}
	return false
}

// analyzeTrust classifies a role's trust policy into assume relationships and
// emits findings for the risky ones (external, wildcard, OIDC without subject).
func analyzeTrust(r state.IAMRole, account string, now time.Time) ([]AssumeRelation, []findings.Finding) {
	var rels []AssumeRelation
	var fs []findings.Finding

	for _, st := range r.TrustPolicy.Statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		hasSubCondition := hasSubjectCondition(st.ConditionKeys)

		for _, principal := range st.AWSPrincipals {
			if principal == "" {
				continue // malformed/empty principal — do not synthesize a relation
			}
			if principal == "*" {
				rel := AssumeRelation{RoleName: r.Name, RoleARN: r.ARN, Source: SourceWildcard, Principal: "*",
					Risky: true, Reason: "trust policy allows any principal to assume the role"}
				rels = append(rels, rel)
				fs = append(fs, trustFinding(r, findings.SeverityCritical,
					"IAM role trusts any principal (Principal: \"*\")",
					"aws_iam_role_trust_wildcard_principal", rel.Reason,
					"Restrict the AssumeRole trust policy to specific principals and add a Condition.", now))
				continue
			}
			// Fail safe: when the scan account is unknown (account == ""), an
			// account-bearing principal is treated as external rather than
			// silently assumed intra-account — a security tool must not fail open
			// on its highest-severity check.
			if acct := accountFromARN(principal); acct != "" && acct != account {
				rel := AssumeRelation{RoleName: r.Name, RoleARN: r.ARN, Source: SourceExternal, Principal: principal,
					Risky: true, Reason: fmt.Sprintf("trust policy allows external account %s to assume the role", acct)}
				rels = append(rels, rel)
				fs = append(fs, trustFinding(r, findings.SeverityHigh,
					"IAM role trusts an external AWS account",
					"aws_iam_role_trust_external_account", rel.Reason,
					"Confirm the cross-account trust is intended and constrained with an ExternalId or aws:SourceArn/SourceAccount condition.", now))
				continue
			}
			// Same-account principal: an intra-account assume edge for the graph.
			rels = append(rels, AssumeRelation{RoleName: r.Name, RoleARN: r.ARN, Source: SourceIntraAccount,
				Principal: principal, Reason: "intra-account principal may assume the role"})
		}

		for _, fed := range st.Federated {
			low := strings.ToLower(fed)
			switch {
			case strings.Contains(low, ":oidc-provider/"):
				risky := !hasSubCondition
				rel := AssumeRelation{RoleName: r.Name, RoleARN: r.ARN, Source: SourceOIDC, Principal: fed,
					Risky: risky, Reason: "OIDC federation"}
				if risky {
					rel.Reason = "OIDC federation without a subject (sub/aud) condition — any identity from the provider can assume the role"
					fs = append(fs, trustFinding(r, findings.SeverityHigh,
						"IAM role trusts an OIDC provider without a subject condition",
						"aws_iam_oidc_trust_no_subject_condition", rel.Reason,
						"Add a StringEquals/StringLike condition on the provider's :sub (and :aud) so only intended workloads can assume the role.", now))
				}
				rels = append(rels, rel)
			case strings.Contains(low, ":saml-provider/"):
				rels = append(rels, AssumeRelation{RoleName: r.Name, RoleARN: r.ARN, Source: SourceSAML,
					Principal: fed, Reason: "SAML federation"})
			}
		}
	}
	return rels, fs
}

// hasSubjectCondition reports whether any condition key constrains the federated
// subject or audience (the keys end in ":sub" or ":aud").
func hasSubjectCondition(keys []string) bool {
	for _, k := range keys {
		lk := strings.ToLower(k)
		if strings.HasSuffix(lk, ":sub") || strings.HasSuffix(lk, ":aud") {
			return true
		}
	}
	return false
}

// accountFromARN extracts the account id from a principal, or "" if it carries
// no account. It handles both full ARNs and the bare 12-digit account-id
// shorthand (e.g. "123456789012", equivalent to arn:aws:iam::123456789012:root)
// — missing the shorthand would misclassify external cross-account trust as
// intra-account, a security-relevant false negative.
func accountFromARN(arn string) string {
	if len(arn) == 12 && isAllDigits(arn) {
		return arn
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 5 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func privilegeFindings(p Privilege, now time.Time) []findings.Finding {
	var fs []findings.Finding
	res := findings.Resource{
		ID: principalID(p), Name: p.Name, Type: "aws_iam_" + p.Kind, Provider: "aws",
	}
	// Admin via the AdministratorAccess managed policy on a user is already
	// reported by the aws_iam_user_admin_policy check; only report admin granted
	// through a custom/inline wildcard here to avoid a duplicate finding.
	if p.AdminViaPolicy {
		fs = append(fs, findings.Finding{
			ID:       "aws_iam_admin_via_policy::" + res.ID,
			CheckID:  "aws_iam_admin_via_policy",
			Title:    "IAM principal has administrator-equivalent permissions",
			Severity: findings.SeverityHigh,
			Status:   findings.StatusOpen,
			Provider: "aws", Service: "iam", Resource: res,
			Description: fmt.Sprintf("%s %q is granted full administrative access (Action \"*\" on Resource \"*\" or AdministratorAccess).", p.Kind, p.Name),
			Rationale:   "An administrator-equivalent principal can perform any action in the account; it is the highest-value target.",
			Impact:      "Compromise of this principal is compromise of the entire account.",
			Remediation: "Apply least privilege: replace the wildcard grant with the specific actions/resources the principal needs.",
			Reachable:   findings.ReachUnknown,
			FirstSeen:   now, LastSeen: now,
		})
	}
	if len(p.Privesc) > 0 {
		fs = append(fs, findings.Finding{
			ID:       "aws_iam_privilege_escalation::" + res.ID,
			CheckID:  "aws_iam_privilege_escalation",
			Title:    "IAM principal holds privilege-escalation permissions",
			Severity: findings.SeverityHigh,
			Status:   findings.StatusOpen,
			Provider: "aws", Service: "iam", Resource: res,
			Description: fmt.Sprintf("%s %q can escalate privileges via: %s (granted on Resource \"*\").", p.Kind, p.Name, strings.Join(p.Privesc, ", ")),
			Rationale:   "These actions let a principal grant itself additional permissions, reaching administrative access indirectly.",
			Impact:      "An attacker controlling this principal can escalate to full account control.",
			Remediation: "Scope these actions to specific resources, or remove them; never grant them on Resource \"*\".",
			Reachable:   findings.ReachUnknown,
			FirstSeen:   now, LastSeen: now,
		})
	}
	return fs
}

func trustFinding(r state.IAMRole, sev findings.Severity, title, checkID, desc, remediation string, now time.Time) findings.Finding {
	res := findings.Resource{ID: "role/" + r.Name, Name: r.Name, Type: "aws_iam_role", Provider: "aws", ARN: r.ARN}
	return findings.Finding{
		ID:       checkID + "::" + res.ID,
		CheckID:  checkID,
		Title:    title,
		Severity: sev,
		Status:   findings.StatusOpen,
		Provider: "aws", Service: "iam", Resource: res,
		Description: desc,
		Rationale:   "Over-broad or unconditional trust lets principals outside your control assume the role and inherit its permissions.",
		Impact:      "An attacker who satisfies the trust can assume the role and act with its privileges.",
		Remediation: remediation,
		Reachable:   findings.ReachUnknown,
		FirstSeen:   now, LastSeen: now,
	}
}

func principalID(p Privilege) string { return p.Kind + "/" + p.Name }
