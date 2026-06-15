package k8s

import (
	"fmt"
	"sort"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(exposedSecret{}) }

// exposedSecret reports credential material the Kubernetes secrets collector
// (§9.2) found where it does not belong: ConfigMap data and literal pod
// container environment variables. These are readable by any principal able to
// get the ConfigMap or pod spec — a far wider audience than a properly-mounted
// Secret — so each is a real disclosure regardless of liveness.
//
// Hits are grouped per context into one aggregate finding each, carrying only
// the masked rendering.
type exposedSecret struct{}

func (exposedSecret) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:        "k8s_exposed_secret",
		Title:     "Secret material embedded in the Kubernetes control plane",
		Provider:  "k8s",
		Service:   "secrets",
		Severity:  findings.SeverityHigh,
		Rationale: "Credentials placed in ConfigMap data or literal pod env vars are stored in plaintext in etcd and readable by every principal with get/list on those objects — a much wider audience than a mounted Secret with scoped RBAC.",
		Impact:    "An attacker who can read ConfigMaps or pod specs lifts the credential (database password, API token, key) and uses it directly for data access or lateral movement.",
		Remediation: "Move the value into a Secret and reference it via valueFrom.secretKeyRef (or an external secrets store), and rotate the exposed credential since it must be treated as compromised.",
		References: []string{
			"https://kubernetes.io/docs/concepts/configuration/secret/",
			"https://kubernetes.io/docs/concepts/security/secrets-good-practices/",
		},
	}
}

func (c exposedSecret) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil || len(st.K8s.SecretHits) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()

	// Group by context so each finding is scoped to one cluster.
	byCtx := map[string][]findings.Affected{}
	for _, h := range st.K8s.SecretHits {
		byCtx[h.Account] = append(byCtx[h.Account], findings.Affected{
			Type: "secret",
			ID:   h.Resource,
			Detail: fmt.Sprintf("%s (%s) in %s %s [%s] at %q",
				h.Kind, h.Detector, k8sSurfaceLabel(h.Surface), h.Resource, h.Masked, h.Locator),
		})
	}

	contexts := make([]string, 0, len(byCtx))
	for c := range byCtx {
		contexts = append(contexts, c)
	}
	sort.Strings(contexts)

	var out []findings.Finding
	for _, ctxName := range contexts {
		items := byCtx[ctxName]
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		scope := findings.Resource{
			ID: ctxName, Name: ctxName, Type: "k8s_context", Provider: "k8s", Account: ctxName,
		}
		desc := fmt.Sprintf("%d secret(s) are embedded in the Kubernetes control plane (ConfigMap data / literal pod env) in context %s. Values are shown masked; rotate each, as exposure means compromise.", len(items), ctxName)
		out = append(out, findings.NewAggregate(c.Spec(), scope, desc, items, now))
	}
	return out, nil
}

// k8sSurfaceLabel renders a state surface id for the finding detail.
func k8sSurfaceLabel(surface string) string {
	switch surface {
	case "k8s_configmap":
		return "ConfigMap data"
	case "k8s_pod_env":
		return "pod env var"
	default:
		return surface
	}
}
