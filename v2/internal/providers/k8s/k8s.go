// Package k8s contains read-only Kubernetes collectors. Each collector builds a
// clientset per in-scope kubeconfig context (plan §9.4) and populates the
// normalized state model. Collectors no-op for non-K8s scans and tolerate
// per-context failures so one unreachable cluster does not blank the rest.
package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"

	"github.com/Su1ph3r/nubicustos/internal/engine"
)

// clientsets builds a clientset for each in-scope cluster, paired with its
// context name. A cluster whose clientset cannot be built is reported as an
// error (not silently dropped) so a context never silently contributes nothing.
func clientsets(sc *engine.ScanContext) (map[string]*kubernetes.Clientset, []error) {
	out := map[string]*kubernetes.Clientset{}
	var errs []error
	for _, c := range sc.K8s.Clusters {
		cs, err := kubernetes.NewForConfig(c.Config)
		if err != nil {
			errs = append(errs, fmt.Errorf("k8s: building client for context %s: %w", c.Context, err))
			continue
		}
		out[c.Context] = cs
	}
	return out, errs
}

// boolVal dereferences a *bool, treating nil as false.
func boolVal(p *bool) bool { return p != nil && *p }
