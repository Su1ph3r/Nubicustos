package gcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(crossProjectSA{}) }

// crossProjectSA flags project IAM bindings that grant a role to a user-managed
// service account belonging to a *different* project — the GCP external-trust
// surface (plan §9.3). A service account from another project holding a role here
// is a cross-project trust relationship: compromise of that SA (or its project)
// grants access into this one, and such grants are easy to leave in place
// unnoticed.
//
// Google-managed service agents (gcp-sa-*) are excluded — those cross-project
// grants are made by Google for first-party services and are expected.
type crossProjectSA struct{}

func (crossProjectSA) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "gcp_iam_cross_project_service_account", Title: "Project IAM grants a role to a service account from another project",
		Provider: "gcp", Service: "iam", Severity: findings.SeverityMedium,
		Rationale:   "A user-managed service account from a different project holding a role here is a cross-project trust edge: whoever controls that SA (or compromises its project) inherits this access. These grants accumulate silently and widen the blast radius across project boundaries.",
		Impact:      "Compromise of the external service account or its project extends directly into this project with the granted role.",
		Remediation: "Remove the binding if the cross-project trust is not required, or replace it with a dedicated in-project identity: gcloud projects remove-iam-policy-binding <project> --member='serviceAccount:<sa>' --role=<role>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS GCP 2.0", Control: "1.x"}},
	}
}

func (c crossProjectSA) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, b := range st.GCP.IAMBindings {
		for _, m := range b.Members {
			saProject, ok := userManagedSAProject(m)
			if !ok || saProject == b.Project {
				continue
			}
			res := findings.Resource{
				ID: b.Project + ":" + b.Role, Name: b.Role, Type: "gcp_iam_binding", Provider: "gcp", Account: b.Project,
			}
			desc := fmt.Sprintf("Project %s grants %s to service account %q from project %s (cross-project trust).",
				b.Project, b.Role, strings.TrimPrefix(m, "serviceAccount:"), saProject)
			poc := fmt.Sprintf("gcloud projects get-iam-policy %s --flatten=bindings[].members --filter='bindings.role=%s'", b.Project, b.Role)
			out = append(out, findings.New(c.Spec(), res, desc, poc, now))
		}
	}
	return out, nil
}

// userManagedSAProject extracts the owning project of a user-managed service
// account member (serviceAccount:<name>@<project>.iam.gserviceaccount.com),
// returning ok=false for non-SA members and Google-managed service agents
// (gcp-sa-*), whose cross-project grants are first-party and expected.
func userManagedSAProject(member string) (string, bool) {
	const prefix = "serviceAccount:"
	const suffix = ".iam.gserviceaccount.com"
	if !strings.HasPrefix(member, prefix) {
		return "", false
	}
	email := strings.TrimPrefix(member, prefix)
	at := strings.IndexByte(email, '@')
	if at < 0 {
		return "", false
	}
	domain := email[at+1:]
	if !strings.HasSuffix(domain, suffix) {
		return "", false // not a user-managed SA (e.g. @appspot/@developer/@cloudservices)
	}
	project := strings.TrimSuffix(domain, suffix)
	if project == "" || strings.HasPrefix(project, "gcp-sa-") {
		return "", false // Google-managed service agent — expected to be cross-project
	}
	return project, true
}
