package auth

import (
	"fmt"
	"sort"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sCluster pairs a kubeconfig context name with its resolved REST config.
type K8sCluster struct {
	Context string
	Config  *rest.Config
}

// K8sContextError records a kubeconfig context that could not be resolved or
// reached, with the reason — so an estate check can skip it rather than abort.
type K8sContextError struct {
	Context string
	Reason  string
}

// ResolveK8s loads the kubeconfig and resolves the requested contexts to REST
// configs (plan §9.4 — iterate kubeconfig contexts). With no contexts requested
// it uses the current context. It validates each by querying the server version
// up front, so an unreachable cluster or bad credential fails before the scan
// fans out.
func ResolveK8s(contexts []string) ([]K8sCluster, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := loadingRules.Load()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}

	if len(contexts) == 0 {
		if raw.CurrentContext == "" {
			return nil, fmt.Errorf("no current kubeconfig context set (use --context)")
		}
		contexts = []string{raw.CurrentContext}
	}

	var clusters []K8sCluster
	for _, name := range contexts {
		if _, ok := raw.Contexts[name]; !ok {
			return nil, fmt.Errorf("kubeconfig has no context %q", name)
		}
		cfg, err := clientcmd.NewNonInteractiveClientConfig(*raw, name, &clientcmd.ConfigOverrides{}, loadingRules).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("building client config for context %q: %w", name, err)
		}
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("building clientset for context %q: %w", name, err)
		}
		if _, err := clientset.Discovery().ServerVersion(); err != nil {
			return nil, fmt.Errorf("validating context %q: %w", name, err)
		}
		clusters = append(clusters, K8sCluster{Context: name, Config: cfg})
	}
	return clusters, nil
}

// ResolveK8sAll resolves every context defined in the kubeconfig, for an
// estate-wide check (plan §9.4). Unlike ResolveK8s it is fault-tolerant: a
// context that cannot be built or reached is returned in the failures slice with
// its reason rather than aborting the whole set — so one expired or unreachable
// cluster never sinks an estate preflight. A hard error is returned only when the
// kubeconfig itself cannot be loaded or defines no contexts.
func ResolveK8sAll() (clusters []K8sCluster, failures []K8sContextError, err error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	raw, err := loadingRules.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	if len(raw.Contexts) == 0 {
		return nil, nil, fmt.Errorf("kubeconfig defines no contexts")
	}

	names := make([]string, 0, len(raw.Contexts))
	for name := range raw.Contexts {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order across runs

	for _, name := range names {
		cfg, err := clientcmd.NewNonInteractiveClientConfig(*raw, name, &clientcmd.ConfigOverrides{}, loadingRules).ClientConfig()
		if err != nil {
			failures = append(failures, K8sContextError{name, "building client config: " + err.Error()})
			continue
		}
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			failures = append(failures, K8sContextError{name, "building clientset: " + err.Error()})
			continue
		}
		if _, err := clientset.Discovery().ServerVersion(); err != nil {
			failures = append(failures, K8sContextError{name, "unreachable: " + err.Error()})
			continue
		}
		clusters = append(clusters, K8sCluster{Context: name, Config: cfg})
	}
	return clusters, failures, nil
}
