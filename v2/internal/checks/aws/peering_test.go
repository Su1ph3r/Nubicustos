package aws

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestVPCPeeringLateralExposureCheck(t *testing.T) {
	st := state.New()
	st.AddRouteTable(state.RouteTable{ID: "rt-pub", VPCID: "vpc-pub", IGWRoute: true, PeeringIDs: []string{"pcx-1"}})
	st.AddRouteTable(state.RouteTable{ID: "rt-priv", VPCID: "vpc-priv", PeeringIDs: []string{"pcx-1"}})
	st.AddVPCPeering(state.VPCPeering{ID: "pcx-1", Region: "us-east-1", VPCA: "vpc-pub", VPCB: "vpc-priv", Active: true})

	fs, err := vpcPeeringLateralExposure{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Resource.ID != "vpc-priv" || f.CheckID != "aws_vpc_peering_lateral_exposure" {
		t.Fatalf("unexpected finding resource/check: %s / %s", f.Resource.ID, f.CheckID)
	}
	if !strings.Contains(f.Description, "vpc-pub") || !strings.Contains(f.Description, "pcx-1") {
		t.Errorf("description should name the internet VPC and peering: %q", f.Description)
	}
}

func TestVPCPeeringLateralExposureNoPeering(t *testing.T) {
	st := state.New()
	st.AddRouteTable(state.RouteTable{ID: "rt", VPCID: "vpc-1", IGWRoute: true})
	if fs, _ := (vpcPeeringLateralExposure{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("no peering should yield no findings, got %d", len(fs))
	}
}
