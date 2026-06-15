package preflight

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// gcpRemediator renders access gaps as a GCP IAM fix: predefined roles to grant
// plus a least-privilege custom role definition (the file `gcloud iam roles
// create --file` consumes) of exactly the missing permissions.
type gcpRemediator struct {
	project string
}

// NewGCPRemediator returns the GCP IAM remediator. project is used only in the
// guidance text (custom roles are created under a project or org).
func NewGCPRemediator(project string) Remediator { return gcpRemediator{project: project} }

func (r gcpRemediator) Build(t Tool, tr ToolReport) Remediation {
	rem := Remediation{
		PolicyName:      t.RemediationPolicyName,
		ManagedPolicies: append([]string(nil), t.RequiredManagedPolicies...), // predefined GCP role names
	}
	if tr.Readiness == ReadinessReady {
		rem.Summary = fmt.Sprintf("%s: all %d required permission(s) present — ready.", t.Name, len(tr.Allowed))
		return rem
	}

	missing := append([]string(nil), tr.Denied...)
	sort.Strings(missing)
	if len(missing) > 0 {
		rem.PolicyDocument = gcpCustomRole(t.RemediationPolicyName, missing)
	}

	var parts []string
	if len(missing) > 0 {
		fix := fmt.Sprintf("create and grant the generated %s custom role", t.RemediationPolicyName)
		if len(t.RequiredManagedPolicies) > 0 {
			fix = fmt.Sprintf("grant %s, or %s", strings.Join(t.RequiredManagedPolicies, " + "), fix)
		}
		parts = append(parts, fmt.Sprintf("missing %d permission(s) — %s", len(missing), fix))
	}
	if len(tr.Unknown) > 0 {
		parts = append(parts, fmt.Sprintf("%d permission(s) could not be verified — grant resourcemanager.projects.getIamPolicy for an authoritative check", len(tr.Unknown)))
	}
	rem.Summary = fmt.Sprintf("%s [%s]: %s.", t.Name, tr.Readiness, strings.Join(parts, "; "))
	return rem
}

// gcpCustomRole renders a custom-role definition granting exactly permissions,
// ready for `gcloud iam roles create <id> --project <p> --file <file>` (gcloud
// accepts JSON or YAML).
func gcpCustomRole(name string, permissions []string) string {
	if name == "" {
		name = "NubicustosGcpPreflightRole"
	}
	doc := map[string]any{
		"title":               name,
		"description":         "Least-privilege read access for Nubicustos GCP scanning.",
		"stage":               "GA",
		"includedPermissions": permissions,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
