package gcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(iamPublicMember{})
	engine.RegisterCheck(iamPrimitiveRole{})
}

// primitiveRoles are the broad legacy roles that should be replaced with
// predefined/custom least-privilege roles.
var primitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
}

func isPublicMember(m string) bool {
	return m == "allUsers" || m == "allAuthenticatedUsers"
}

type iamPublicMember struct{}

func (iamPublicMember) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_iam_public_member", Title: "Project IAM grants a role to all users",
		Provider: "gcp", Service: "iam", Severity: findings.SeverityHigh,
		Rationale:   "A binding to allUsers or allAuthenticatedUsers grants the role to anyone on the internet.",
		Impact:      "Any internet principal inherits the bound role's permissions on the project.",
		Remediation: "Remove the public member: gcloud projects remove-iam-policy-binding <project> --member allUsers --role <role>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "1.x"}},
	}
}

func (c iamPublicMember) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, b := range st.GCP.IAMBindings {
		var public []string
		for _, m := range b.Members {
			if isPublicMember(m) {
				public = append(public, m)
			}
		}
		if len(public) == 0 {
			continue
		}
		res := findings.Resource{
			ID: b.Project + ":" + b.Role, Name: b.Role, Type: "gcp_project_iam_binding", Provider: "gcp", Account: b.Project,
		}
		desc := fmt.Sprintf("Project %s grants %s to %s.", b.Project, b.Role, strings.Join(public, ", "))
		poc := fmt.Sprintf("gcloud projects get-iam-policy %s --format=json", b.Project)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

type iamPrimitiveRole struct{}

func (iamPrimitiveRole) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_iam_primitive_role", Title: "Project IAM uses a broad primitive role",
		Provider: "gcp", Service: "iam", Severity: findings.SeverityMedium,
		Rationale:   "The primitive roles owner/editor grant sweeping permissions across the project, violating least privilege.",
		Impact:      "A compromise of any member bound to owner/editor is a near-total project compromise.",
		Remediation: "Replace primitive roles with predefined or custom least-privilege roles.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "1.x"}},
	}
}

func (c iamPrimitiveRole) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, b := range st.GCP.IAMBindings {
		if !primitiveRoles[b.Role] || len(b.Members) == 0 {
			continue
		}
		res := findings.Resource{
			ID: b.Project + ":" + b.Role, Name: b.Role, Type: "gcp_project_iam_binding", Provider: "gcp", Account: b.Project,
		}
		desc := fmt.Sprintf("Project %s binds the primitive role %s to %d member(s).", b.Project, b.Role, len(b.Members))
		poc := fmt.Sprintf("gcloud projects get-iam-policy %s --format=json", b.Project)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
