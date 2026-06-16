package aws

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestSGTransitiveWorldOpen(t *testing.T) {
	st := state.New()
	// web-sg is world-open on SSH; db-sg admits web-sg on 5432 but has no
	// world-open rule of its own; isolated-sg references only a non-world group.
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-web", Name: "web", Region: "us-east-1", VPCID: "vpc-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, OpenV4: true, IPv4CIDRs: []string{"0.0.0.0/0"}}},
	})
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-db", Name: "db", Region: "us-east-1", VPCID: "vpc-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 5432, ToPort: 5432, SourceSGs: []string{"sg-web"}}},
	})
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-internal", Name: "internal", Region: "us-east-1", VPCID: "vpc-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, SourceSGs: []string{"sg-db"}}},
	})

	fs, err := sgTransitiveWorldOpen{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	// Only sg-db is transitively exposed (references the world-open sg-web).
	// sg-web is directly world-open (covered elsewhere); sg-internal references
	// only sg-db, which is not itself world-open.
	if len(fs) != 1 || fs[0].Resource.ID != "sg-db" {
		t.Fatalf("expected only sg-db flagged, got %+v", fs)
	}
	if !strings.Contains(fs[0].Description, "sg-web") || !strings.Contains(fs[0].Description, "port 5432") {
		t.Errorf("description should name the world-open source and the port: %q", fs[0].Description)
	}
}

func TestSGTransitiveWorldOpenNoneWhenNoWorldOpen(t *testing.T) {
	st := state.New()
	st.AddSecurityGroup(state.SecurityGroup{
		ID: "sg-a", Name: "a", VPCID: "vpc-1",
		Ingress: []state.IngressRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, SourceSGs: []string{"sg-b"}}},
	})
	st.AddSecurityGroup(state.SecurityGroup{ID: "sg-b", Name: "b", VPCID: "vpc-1"})
	if fs, _ := (sgTransitiveWorldOpen{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("no world-open group means no transitive exposure, got %+v", fs)
	}
}
