package k8s

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(podCollector{}) }

type podCollector struct{}

func (podCollector) Name() string { return "k8s:pods" }

// Collect gathers pod security posture across the in-scope contexts: host
// namespace sharing and per-container privilege/escalation/run-as-root settings.
func (podCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "k8s" {
		return nil
	}
	csByCtx, errs := clientsets(sc)
	for ctxName, cs := range csByCtx {
		list, err := cs.CoreV1().Pods("").List(sc.Ctx, metav1.ListOptions{})
		if err != nil {
			errs = append(errs, fmt.Errorf("k8s pods: listing pods in context %s: %w", ctxName, err))
			continue
		}
		for i := range list.Items {
			st.AddK8sPod(normalizePod(ctxName, &list.Items[i]))
		}
	}
	return errors.Join(errs...)
}

func normalizePod(ctxName string, p *corev1.Pod) state.K8sPod {
	out := state.K8sPod{
		Name:        p.Name,
		Namespace:   p.Namespace,
		Context:     ctxName,
		HostNetwork: p.Spec.HostNetwork,
		HostPID:     p.Spec.HostPID,
		HostIPC:     p.Spec.HostIPC,
	}
	// Pod-level defaults for the run-as identity; containers may override them.
	var podRunAsNonRoot *bool
	var podRunAsUser *int64
	if p.Spec.SecurityContext != nil {
		podRunAsNonRoot = p.Spec.SecurityContext.RunAsNonRoot
		podRunAsUser = p.Spec.SecurityContext.RunAsUser
	}
	for i := range p.Spec.Containers {
		out.Containers = append(out.Containers, normalizeContainer(&p.Spec.Containers[i], podRunAsNonRoot, podRunAsUser))
	}
	return out
}

func normalizeContainer(c *corev1.Container, podRunAsNonRoot *bool, podRunAsUser *int64) state.K8sContainer {
	out := state.K8sContainer{Name: c.Name, Image: c.Image}
	sec := c.SecurityContext

	out.Privileged = sec != nil && boolVal(sec.Privileged)

	// allowPrivilegeEscalation defaults to true when unset; record the effective
	// "is escalation allowed" value (true = not explicitly disabled).
	out.AllowPrivilegeEscalation = true
	if sec != nil && sec.AllowPrivilegeEscalation != nil {
		out.AllowPrivilegeEscalation = *sec.AllowPrivilegeEscalation
	}

	// run-as-non-root: a container is treated as non-root if runAsNonRoot is true
	// OR an effective runAsUser (container over pod) is set to a non-zero UID.
	// Either signal alone prevents the container from running as root, so missing
	// only the boolean (the common "runAsUser: 1000" pattern) is not a finding.
	out.RunAsNonRoot = effectiveRunAsNonRoot(sec, podRunAsNonRoot, podRunAsUser)
	return out
}

func effectiveRunAsNonRoot(sec *corev1.SecurityContext, podRunAsNonRoot *bool, podRunAsUser *int64) bool {
	// runAsNonRoot: container value overrides the pod value.
	switch {
	case sec != nil && sec.RunAsNonRoot != nil:
		if *sec.RunAsNonRoot {
			return true
		}
	case podRunAsNonRoot != nil:
		if *podRunAsNonRoot {
			return true
		}
	}
	// runAsUser: container value overrides the pod value; any non-zero UID is
	// non-root.
	uid := podRunAsUser
	if sec != nil && sec.RunAsUser != nil {
		uid = sec.RunAsUser
	}
	return uid != nil && *uid != 0
}
