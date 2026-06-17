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

func TestTGWLateralExposureCheck(t *testing.T) {
	st := state.New()
	st.AddRouteTable(state.RouteTable{ID: "rt-pub", VPCID: "vpc-pub", IGWRoute: true, TransitGatewayIDs: []string{"tgw-1"}})
	st.AddRouteTable(state.RouteTable{ID: "rt-priv", VPCID: "vpc-priv", TransitGatewayIDs: []string{"tgw-1"}})
	st.AddTGWAttachment(state.TGWAttachment{TgwID: "tgw-1", VPCID: "vpc-pub", Region: "us-east-1", Available: true})
	st.AddTGWAttachment(state.TGWAttachment{TgwID: "tgw-1", VPCID: "vpc-priv", Region: "us-east-1", Available: true})

	fs, err := tgwLateralExposure{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Resource.ID != "vpc-priv" {
		t.Fatalf("expected vpc-priv flagged, got %+v", fs)
	}
	if !strings.Contains(fs[0].Description, "tgw-1") || !strings.Contains(fs[0].Description, "vpc-pub") {
		t.Errorf("description should name the transit gateway and internet VPC: %q", fs[0].Description)
	}
	// The peering-only check must not fire for a TGW bridge.
	if pf, _ := (vpcPeeringLateralExposure{}).Evaluate(nil, st); len(pf) != 0 {
		t.Fatalf("peering check should not fire for a TGW bridge, got %+v", pf)
	}
}
