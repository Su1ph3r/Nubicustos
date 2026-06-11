package k8s

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(clusterAdminBinding{})
	engine.RegisterCheck(wildcardRole{})
}

// broadSubject reports whether an RBAC subject ("Kind/name") grants access to a
// wide, untrusted population: anonymous, all (un)authenticated users, all
// service accounts cluster-wide, or all service accounts in a namespace
// (system:serviceaccounts:<ns>, which covers every default SA in that namespace).
func broadSubject(subject string) bool {
	switch subject {
	case "Group/system:authenticated", "Group/system:unauthenticated",
		"User/system:anonymous", "Group/system:serviceaccounts":
		return true
	}
	return strings.HasPrefix(subject, "Group/system:serviceaccounts:")
}

type clusterAdminBinding struct{}

func (clusterAdminBinding) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "k8s_cluster_admin_binding", Title: "cluster-admin is bound to a broad subject",
		Provider: "k8s", Service: "rbac", Severity: findings.SeverityCritical,
		Rationale:   "Binding cluster-admin to an anonymous, all-authenticated, or all-service-accounts subject grants full cluster control to a wide population.",
		Impact:      "Any principal matching the subject can do anything in the cluster.",
		Remediation: "Remove the binding or scope it to specific, named subjects: kubectl delete clusterrolebinding <name>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Kubernetes", Control: "5.1.1"}},
	}
}

func (c clusterAdminBinding) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	admin := effectiveAdminRoles(st.K8s)

	var out []findings.Finding
	for _, b := range st.K8s.Bindings {
		// Treat the binding as granting admin if it references the built-in
		// cluster-admin role OR a custom role that is effectively cluster-admin
		// (verb "*" on resource "*"). A god-role under a different name bound to a
		// broad subject is the same total compromise.
		if b.RoleRef != "cluster-admin" && !admin[adminKey(b.Context, b.RoleRef)] {
			continue
		}
		var broad []string
		for _, s := range b.Subjects {
			if broadSubject(s) {
				broad = append(broad, s)
			}
		}
		if len(broad) == 0 {
			continue
		}
		res := findings.Resource{
			ID: b.Name, Name: b.Name, Type: "k8s_" + lowerKind(b.Kind), Provider: "k8s",
			Account: b.Context, Region: b.Namespace,
		}
		desc := fmt.Sprintf("%s %q binds %s (cluster-admin-equivalent) to %s.", b.Kind, b.Name, b.RoleRef, strings.Join(broad, ", "))
		poc := fmt.Sprintf("kubectl get %s %s -o yaml", lowerKind(b.Kind), b.Name)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

// effectiveAdminRoles indexes the ClusterRoles that are effectively cluster-admin
// (wildcard verb on wildcard resource) by context+name, so a binding can be
// recognized as admin-granting even under a custom role name.
func effectiveAdminRoles(k *state.K8s) map[string]bool {
	admin := map[string]bool{}
	for _, r := range k.Roles {
		if r.Kind == "ClusterRole" && r.WildcardVerb && r.WildcardResource {
			admin[adminKey(r.Context, r.Name)] = true
		}
	}
	return admin
}

func adminKey(ctx, name string) string { return ctx + "/" + name }

type wildcardRole struct{}

func (wildcardRole) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "k8s_wildcard_role", Title: "Role grants wildcard verbs on wildcard resources",
		Provider: "k8s", Service: "rbac", Severity: findings.SeverityHigh,
		Rationale:   "A rule granting verb \"*\" on resource \"*\" is effectively admin within its scope and defeats least privilege.",
		Impact:      "Any subject bound to the role can perform every action on every resource in scope.",
		Remediation: "Replace the wildcard rule with explicit verbs and resources.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Kubernetes", Control: "5.1.3"}},
	}
}

func (c wildcardRole) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, r := range st.K8s.Roles {
		if !(r.WildcardVerb && r.WildcardResource) {
			continue
		}
		res := findings.Resource{
			ID: r.Name, Name: r.Name, Type: "k8s_" + lowerKind(r.Kind), Provider: "k8s",
			Account: r.Context, Region: r.Namespace,
		}
		desc := fmt.Sprintf("%s %q grants verb \"*\" on resource \"*\".", r.Kind, r.Name)
		poc := fmt.Sprintf("kubectl get %s %s -o yaml", lowerKind(r.Kind), r.Name)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

func lowerKind(kind string) string { return strings.ToLower(kind) }
