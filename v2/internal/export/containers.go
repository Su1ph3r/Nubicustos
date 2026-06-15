package export

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

// ContainersSchemaVersion versions the container-inventory JSON so Cepheus can
// ingest it stably across releases.
const ContainersSchemaVersion = "1.0"

// ContainerInventory is the nubicustos-containers.json document consumed by
// Cepheus for container-escape modeling: every container collected from the
// scanned Kubernetes contexts, with its image and the security-relevant pod/
// container posture that informs escape paths.
type ContainerInventory struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	Containers    []ContainerItem `json:"containers"`
}

// ContainerItem is one container's inventory record.
type ContainerItem struct {
	Context                  string `json:"context"`
	Namespace                string `json:"namespace"`
	Pod                      string `json:"pod"`
	Container                string `json:"container"`
	Image                    string `json:"image"`
	Privileged               bool   `json:"privileged"`
	AllowPrivilegeEscalation bool   `json:"allow_privilege_escalation"`
	RunAsNonRoot             bool   `json:"run_as_non_root"`
	HostNetwork              bool   `json:"host_network"`
	HostPID                  bool   `json:"host_pid"`
	HostIPC                  bool   `json:"host_ipc"`
}

// Containers writes the container inventory derived from the collected
// Kubernetes state. It is emitted at scan time (the inventory is state, not a
// persisted finding). A nil or non-Kubernetes state yields an empty-but-valid
// document so the downstream contract is always satisfiable.
func Containers(w io.Writer, st *state.State, generatedAt time.Time) error {
	inv := ContainerInventory{
		SchemaVersion: ContainersSchemaVersion,
		GeneratedAt:   generatedAt.UTC().Format(time.RFC3339),
		Containers:    []ContainerItem{},
	}
	if st != nil && st.K8s != nil {
		for _, p := range st.K8s.Pods {
			for _, c := range p.Containers {
				inv.Containers = append(inv.Containers, ContainerItem{
					Context:                  p.Context,
					Namespace:                p.Namespace,
					Pod:                      p.Name,
					Container:                c.Name,
					Image:                    c.Image,
					Privileged:               c.Privileged,
					AllowPrivilegeEscalation: c.AllowPrivilegeEscalation,
					RunAsNonRoot:             c.RunAsNonRoot,
					HostNetwork:              p.HostNetwork,
					HostPID:                  p.HostPID,
					HostIPC:                  p.HostIPC,
				})
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}
