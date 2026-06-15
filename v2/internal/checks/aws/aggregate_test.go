package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

// TestConfigAggregatesPerRegion proves the region-meta check emits a single
// finding listing exactly the non-compliant regions (not one finding per region).
func TestConfigAggregatesPerRegion(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("123456789012")
	st.SetConfigStatus("us-east-1", state.ConfigStatus{Recording: true, AllSupported: true}) // compliant
	st.SetConfigStatus("us-west-2", state.ConfigStatus{})                                    // not recording
	st.SetConfigStatus("eu-west-1", state.ConfigStatus{Recording: true})                     // not all-supported

	fs, err := configRecording{}.Evaluate(nil, st)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 aggregate finding, got %d", len(fs))
	}
	if len(fs[0].Affected) != 2 {
		t.Fatalf("expected 2 affected regions, got %d: %+v", len(fs[0].Affected), fs[0].Affected)
	}
	// Deterministic ordering (sorted by region).
	if fs[0].Affected[0].Region != "eu-west-1" || fs[0].Affected[1].Region != "us-west-2" {
		t.Fatalf("affected items not sorted: %+v", fs[0].Affected)
	}
}

// TestOpenIngressAggregatesSensitiveOnly proves the SG check produces one
// finding listing only the security groups exposing sensitive ports.
func TestOpenIngressAggregatesSensitiveOnly(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("123456789012")
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-ssh", Name: "ssh", Region: "us-east-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true}},
	})
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-app", Name: "app", Region: "us-east-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 8080, ToPort: 8080, OpenV4: true}}, // not sensitive
	})

	fs, err := ec2OpenIngress{}.Evaluate(nil, st)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 aggregate finding, got %d", len(fs))
	}
	if len(fs[0].Affected) != 1 || fs[0].Affected[0].ID != "sg-ssh" {
		t.Fatalf("expected only sg-ssh affected, got %+v", fs[0].Affected)
	}
}
