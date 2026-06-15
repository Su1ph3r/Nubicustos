package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestContainersInventory(t *testing.T) {
	st := state.New()
	st.AddK8sPod(state.K8sPod{
		Name: "web-0", Namespace: "default", Context: "prod", HostNetwork: true,
		Containers: []state.K8sContainer{
			{Name: "app", Image: "registry/app:1.2.3", Privileged: true},
			{Name: "sidecar", Image: "registry/proxy:latest"},
		},
	})

	var buf bytes.Buffer
	if err := Containers(&buf, st, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	var inv ContainerInventory
	if err := json.Unmarshal(buf.Bytes(), &inv); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if inv.SchemaVersion != ContainersSchemaVersion {
		t.Errorf("schema version = %q", inv.SchemaVersion)
	}
	if len(inv.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(inv.Containers))
	}
	app := inv.Containers[0]
	if app.Image != "registry/app:1.2.3" || !app.Privileged || !app.HostNetwork || app.Pod != "web-0" {
		t.Fatalf("container record not populated correctly: %+v", app)
	}
}

func TestContainersNilStateIsValidEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Containers(&buf, nil, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	var inv ContainerInventory
	if err := json.Unmarshal(buf.Bytes(), &inv); err != nil {
		t.Fatalf("nil state must still produce valid JSON: %v", err)
	}
	if inv.Containers == nil {
		t.Error("containers should be an empty array, not null")
	}
}
