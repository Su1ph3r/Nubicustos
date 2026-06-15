package k8s

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(secretsScanCollector{}) }

// secretsScanCollector scans the Kubernetes control plane for credential
// material placed where it does not belong (plan §9.2):
//
//   - ConfigMap data — ConfigMaps are not a secret store, yet database URLs,
//     API tokens, and keys routinely end up in them; any detected secret is a hit.
//   - Literal pod container env vars (env[].value, not valueFrom) — plaintext
//     credentials baked into the pod spec, readable by anyone who can get the pod.
//
// Secret objects themselves are deliberately NOT scanned: they are the intended
// place for secrets, so flagging them would be noise (their risk is over-broad
// RBAC, handled by the trust/RBAC analysis, not secret detection). Only the
// masked detection is recorded; per-context failures are tolerated.
type secretsScanCollector struct{}

func (secretsScanCollector) Name() string { return "k8s:secrets-scan" }

func (secretsScanCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "k8s" {
		return nil
	}
	csByCtx, errs := clientsets(sc)
	for ctxName, cs := range csByCtx {
		// ConfigMap data.
		cms, err := cs.CoreV1().ConfigMaps("").List(sc.Ctx, metav1.ListOptions{})
		if err != nil {
			errs = append(errs, fmt.Errorf("k8s secrets: listing configmaps in context %s: %w", ctxName, err))
		} else {
			for i := range cms.Items {
				cm := &cms.Items[i]
				res := cm.Namespace + "/" + cm.Name
				for k, v := range cm.Data {
					for _, m := range secrets.ScanKeyValue(k, v, k) {
						st.AddK8sSecretHit(k8sSecretHit(m, "k8s_configmap", res, ctxName, k))
					}
				}
			}
		}

		// Literal pod container env vars.
		pods, err := cs.CoreV1().Pods("").List(sc.Ctx, metav1.ListOptions{})
		if err != nil {
			errs = append(errs, fmt.Errorf("k8s secrets: listing pods in context %s: %w", ctxName, err))
			continue
		}
		for i := range pods.Items {
			scanPodEnv(st, ctxName, &pods.Items[i])
		}
	}
	return errors.Join(errs...)
}

// scanPodEnv runs the detector over every literal env var in a pod's containers
// (init + regular). valueFrom references (secretKeyRef/configMapKeyRef) carry no
// inline value and are skipped.
func scanPodEnv(st *state.State, ctxName string, p *corev1.Pod) {
	res := p.Namespace + "/" + p.Name
	scan := func(c *corev1.Container) {
		for _, e := range c.Env {
			if e.Value == "" {
				continue
			}
			locator := c.Name + ":" + e.Name
			for _, m := range secrets.ScanKeyValue(e.Name, e.Value, e.Name) {
				st.AddK8sSecretHit(k8sSecretHit(m, "k8s_pod_env", res, ctxName, locator))
			}
		}
	}
	for i := range p.Spec.InitContainers {
		scan(&p.Spec.InitContainers[i])
	}
	for i := range p.Spec.Containers {
		scan(&p.Spec.Containers[i])
	}
}

// k8sSecretHit folds a detector Match plus its Kubernetes source into a state
// record. Account carries the context; Region is unused for Kubernetes.
func k8sSecretHit(m secrets.Match, surface, resource, ctxName, locator string) state.SecretHit {
	return state.SecretHit{
		Detector: m.Detector,
		Kind:     m.Kind,
		Surface:  surface,
		Resource: resource,
		Account:  ctxName,
		Locator:  locator,
		Masked:   m.Masked,
		LastFour: m.LastFour,
		Entropy:  m.Entropy,
	}
}
