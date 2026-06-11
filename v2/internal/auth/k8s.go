package auth

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sCluster pairs a kubeconfig context name with its resolved REST config.
type K8sCluster struct {
	Context string
	Config  *rest.Config
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
