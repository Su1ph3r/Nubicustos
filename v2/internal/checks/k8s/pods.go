// Package k8s contains native Kubernetes posture checks. Checks read collected
// state and emit findings; they never call the cluster. Each check pairs a
// CheckSpec with per-resource finding generation, mirroring the cloud checks.
package k8s

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(privilegedContainer{})
	engine.RegisterCheck(hostNamespaces{})
	engine.RegisterCheck(privilegeEscalation{})
	engine.RegisterCheck(runAsRoot{})
}

// podResource builds the normalized resource for a pod (context-scoped).
func podResource(p state.K8sPod) findings.Resource {
	return findings.Resource{
		ID: p.Namespace + "/" + p.Name, Name: p.Name, Type: "k8s_pod", Provider: "k8s",
		Account: p.Context, Region: p.Namespace,
	}
}

type privilegedContainer struct{}

func (privilegedContainer) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "k8s_privileged_container", Title: "Pod runs a privileged container",
		Provider: "k8s", Service: "workload", Severity: findings.SeverityHigh,
		Rationale:   "A privileged container has nearly all host capabilities and can access host devices — a container escape is trivial from there.",
		Impact:      "Compromise of the container is effectively compromise of the node.",
		Remediation: "Remove securityContext.privileged: true; grant only the specific capabilities required.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Kubernetes", Control: "5.2.1"}},
	}
}

func (c privilegedContainer) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, p := range st.K8s.Pods {
		for _, ct := range p.Containers {
			if !ct.Privileged {
				continue
			}
			desc := fmt.Sprintf("Container %q in pod %s/%s (context %s) runs privileged.", ct.Name, p.Namespace, p.Name, p.Context)
			poc := fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[*].securityContext.privileged}'", p.Name, p.Namespace)
			out = append(out, findings.New(c.Spec(), podResource(p), desc, poc, now))
		}
	}
	return out, nil
}

type hostNamespaces struct{}

func (hostNamespaces) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "k8s_host_namespace", Title: "Pod shares a host namespace",
		Provider: "k8s", Service: "workload", Severity: findings.SeverityHigh,
		Rationale:   "hostNetwork/hostPID/hostIPC place the pod in the node's namespaces, exposing host processes, network, and IPC.",
		Impact:      "The pod can observe or interfere with host-level processes and traffic, easing escape and lateral movement.",
		Remediation: "Remove hostNetwork/hostPID/hostIPC from the pod spec unless strictly required.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Kubernetes", Control: "5.2.4"}},
	}
}

func (c hostNamespaces) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, p := range st.K8s.Pods {
		if !p.HostNamespaces() {
			continue
		}
		desc := fmt.Sprintf("Pod %s/%s (context %s) shares a host namespace (network=%t pid=%t ipc=%t).",
			p.Namespace, p.Name, p.Context, p.HostNetwork, p.HostPID, p.HostIPC)
		poc := fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.hostNetwork} {.spec.hostPID} {.spec.hostIPC}'", p.Name, p.Namespace)
		out = append(out, findings.New(c.Spec(), podResource(p), desc, poc, now))
	}
	return out, nil
}

type privilegeEscalation struct{}

func (privilegeEscalation) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "k8s_allow_privilege_escalation", Title: "Container allows privilege escalation",
		Provider: "k8s", Service: "workload", Severity: findings.SeverityMedium,
		Rationale:   "allowPrivilegeEscalation defaults to true; leaving it unset lets a process gain more privileges than its parent (e.g. via setuid binaries).",
		Impact:      "A compromised process can escalate within the container, broadening the blast radius.",
		Remediation: "Set securityContext.allowPrivilegeEscalation: false on every container.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Kubernetes", Control: "5.2.5"}},
	}
}

func (c privilegeEscalation) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, p := range st.K8s.Pods {
		for _, ct := range p.Containers {
			// Privileged containers already escalate; report the standalone case.
			if ct.Privileged || !ct.AllowPrivilegeEscalation {
				continue
			}
			desc := fmt.Sprintf("Container %q in pod %s/%s does not disable privilege escalation.", ct.Name, p.Namespace, p.Name)
			poc := fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}'", p.Name, p.Namespace)
			out = append(out, findings.New(c.Spec(), podResource(p), desc, poc, now))
		}
	}
	return out, nil
}

type runAsRoot struct{}

func (runAsRoot) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "k8s_run_as_root", Title: "Container may run as root",
		Provider: "k8s", Service: "workload", Severity: findings.SeverityLow,
		Rationale:   "Without runAsNonRoot, a container image whose default user is root runs as UID 0, maximizing the impact of a compromise.",
		Impact:      "A breakout from a root container starts with full in-container root.",
		Remediation: "Set securityContext.runAsNonRoot: true (at the pod or container level).",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Kubernetes", Control: "5.2.6"}},
	}
}

func (c runAsRoot) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.K8s == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, p := range st.K8s.Pods {
		for _, ct := range p.Containers {
			if ct.RunAsNonRoot {
				continue
			}
			desc := fmt.Sprintf("Container %q in pod %s/%s does not enforce runAsNonRoot.", ct.Name, p.Namespace, p.Name)
			poc := fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.securityContext.runAsNonRoot}'", p.Name, p.Namespace)
			out = append(out, findings.New(c.Spec(), podResource(p), desc, poc, now))
		}
	}
	return out, nil
}
