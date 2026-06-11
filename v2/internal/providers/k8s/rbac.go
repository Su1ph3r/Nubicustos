package k8s

import (
	"errors"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(rbacCollector{}) }

type rbacCollector struct{}

func (rbacCollector) Name() string { return "k8s:rbac" }

// Collect gathers RBAC roles (flagging wildcard verbs/resources) and bindings
// (capturing the referenced role and its subjects) across the in-scope contexts.
func (rbacCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "k8s" {
		return nil
	}
	csByCtx, errs := clientsets(sc)
	for ctxName, cs := range csByCtx {
		rbac := cs.RbacV1()

		if crs, err := rbac.ClusterRoles().List(sc.Ctx, metav1.ListOptions{}); err == nil {
			for i := range crs.Items {
				st.AddK8sRole(roleFromRules(ctxName, "ClusterRole", crs.Items[i].Name, "", crs.Items[i].Rules))
			}
		} else {
			errs = append(errs, fmt.Errorf("k8s rbac: listing clusterroles in context %s: %w", ctxName, err))
		}
		if rs, err := rbac.Roles("").List(sc.Ctx, metav1.ListOptions{}); err == nil {
			for i := range rs.Items {
				st.AddK8sRole(roleFromRules(ctxName, "Role", rs.Items[i].Name, rs.Items[i].Namespace, rs.Items[i].Rules))
			}
		} else {
			errs = append(errs, fmt.Errorf("k8s rbac: listing roles in context %s: %w", ctxName, err))
		}
		if crbs, err := rbac.ClusterRoleBindings().List(sc.Ctx, metav1.ListOptions{}); err == nil {
			for i := range crbs.Items {
				st.AddRBACBinding(state.RBACBinding{
					Name: crbs.Items[i].Name, Context: ctxName, Kind: "ClusterRoleBinding",
					RoleRef:  crbs.Items[i].RoleRef.Name,
					Subjects: subjects(crbs.Items[i].Subjects),
				})
			}
		} else {
			errs = append(errs, fmt.Errorf("k8s rbac: listing clusterrolebindings in context %s: %w", ctxName, err))
		}
		if rbs, err := rbac.RoleBindings("").List(sc.Ctx, metav1.ListOptions{}); err == nil {
			for i := range rbs.Items {
				st.AddRBACBinding(state.RBACBinding{
					Name: rbs.Items[i].Name, Namespace: rbs.Items[i].Namespace, Context: ctxName, Kind: "RoleBinding",
					RoleRef:  rbs.Items[i].RoleRef.Name,
					Subjects: subjects(rbs.Items[i].Subjects),
				})
			}
		} else {
			errs = append(errs, fmt.Errorf("k8s rbac: listing rolebindings in context %s: %w", ctxName, err))
		}
	}
	return errors.Join(errs...)
}

func roleFromRules(ctxName, kind, name, namespace string, rules []rbacv1.PolicyRule) state.K8sRole {
	r := state.K8sRole{Name: name, Namespace: namespace, Context: ctxName, Kind: kind}
	for _, rule := range rules {
		if containsWildcard(rule.Verbs) {
			r.WildcardVerb = true
		}
		if containsWildcard(rule.Resources) {
			r.WildcardResource = true
		}
	}
	return r
}

func containsWildcard(vals []string) bool {
	for _, v := range vals {
		if v == "*" {
			return true
		}
	}
	return false
}

func subjects(subs []rbacv1.Subject) []string {
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, fmt.Sprintf("%s/%s", s.Kind, s.Name))
	}
	return out
}
