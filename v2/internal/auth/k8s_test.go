package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// twoContextKubeconfig defines two contexts pointing at unreachable servers
// (connection refused is immediate, keeping the test fast).
const twoContextKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: c1
  cluster:
    server: https://127.0.0.1:1
- name: c2
  cluster:
    server: https://127.0.0.1:2
users:
- name: u1
  user: {}
contexts:
- name: ctx-a
  context: {cluster: c1, user: u1}
- name: ctx-b
  context: {cluster: c2, user: u1}
current-context: ctx-a
`

func writeKubeconfig(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
}

func TestResolveK8sAllEnumeratesEveryContextAndToleratesFailures(t *testing.T) {
	writeKubeconfig(t, twoContextKubeconfig)

	clusters, failures, err := ResolveK8sAll()
	if err != nil {
		t.Fatalf("a valid multi-context kubeconfig must not hard-error: %v", err)
	}
	// Both contexts are unreachable → both demoted to failures, neither aborting
	// the run. This is the exact regression guard: estate mode must enumerate
	// ALL contexts and skip the bad ones, not stop at the current/first one.
	if len(clusters) != 0 {
		t.Fatalf("unreachable contexts should yield no usable clusters, got %d", len(clusters))
	}
	if len(failures) != 2 {
		t.Fatalf("both contexts should be recorded as failures (enumerate-all + never-abort), got %d: %+v", len(failures), failures)
	}
	seen := map[string]bool{}
	for _, f := range failures {
		seen[f.Context] = true
	}
	if !seen["ctx-a"] || !seen["ctx-b"] {
		t.Fatalf("both ctx-a and ctx-b must be enumerated, got %+v", failures)
	}
}

func TestResolveK8sAllNoContextsErrors(t *testing.T) {
	writeKubeconfig(t, "apiVersion: v1\nkind: Config\n")
	if _, _, err := ResolveK8sAll(); err == nil {
		t.Fatal("a kubeconfig with no contexts should hard-error")
	}
}
