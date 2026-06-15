package reachability

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestSolveAzureNSGExposure(t *testing.T) {
	az := &state.Azure{
		NSGs: []state.NetworkSecurityGroup{
			{ID: "/nsg/public", Name: "public-nsg"},
			{ID: "/nsg/private", Name: "private-nsg"},
			{ID: "/nsg/subnet", Name: "subnet-nsg"},
			{ID: "/nsg/orphan", Name: "orphan-nsg"},
		},
		NICs: []state.AzureNIC{
			{Name: "web", HasPublicIP: true, NSGID: "/nsg/public", SubnetID: "/subnet/a"},
			{Name: "db", HasPublicIP: false, NSGID: "/nsg/private", SubnetID: "/subnet/b"},
			// NIC with a public IP whose exposure comes from the SUBNET NSG.
			{Name: "edge", HasPublicIP: true, NSGID: "", SubnetID: "/subnet/c"},
		},
		SubnetNSGs: []state.AzureSubnetNSG{
			{SubnetID: "/subnet/c", NSGID: "/nsg/subnet"},
		},
	}
	r := SolveAzure(az)

	cases := map[string]findings.Reachability{
		"public-nsg":  findings.ReachYes,     // bound to a public-IP NIC
		"private-nsg": findings.ReachNo,      // governs a NIC, but none public
		"subnet-nsg":  findings.ReachYes,     // public NIC via its subnet
		"orphan-nsg":  findings.ReachUnknown, // not associated with any NIC/subnet
	}
	for name, want := range cases {
		if got := r.verdictByName[name]; got != want {
			t.Errorf("%s reachability = %s, want %s", name, got, want)
		}
	}

	// Annotate marks the NSG open-ingress findings.
	fs := []findings.Finding{
		{CheckID: "azure_nsg_open_ingress", Resource: findings.Resource{Name: "public-nsg"}},
		{CheckID: "azure_nsg_open_ingress", Resource: findings.Resource{Name: "private-nsg"}},
		{CheckID: "azure_storage_blob_public_access", Resource: findings.Resource{Name: "public-nsg"}}, // not annotated
	}
	AnnotateAzure(fs, az, r)
	if fs[0].Reachable != findings.ReachYes {
		t.Errorf("public-nsg finding should be reachable, got %s", fs[0].Reachable)
	}
	if fs[1].Reachable != findings.ReachNo {
		t.Errorf("private-nsg finding should be not-reachable, got %s", fs[1].Reachable)
	}
	if fs[2].Reachable != "" {
		t.Errorf("non-NSG finding must not be annotated, got %s", fs[2].Reachable)
	}
}

func TestSolveAzureNilSafeAndNoTopology(t *testing.T) {
	if r := SolveAzure(nil); r == nil {
		t.Fatal("SolveAzure(nil) must return a usable result")
	}
	// NSGs collected but no NIC topology → unknown, not a false "not reachable".
	az := &state.Azure{NSGs: []state.NetworkSecurityGroup{{ID: "/nsg/x", Name: "x"}}}
	r := SolveAzure(az)
	if got := r.verdictByName["x"]; got != findings.ReachUnknown {
		t.Errorf("no NIC topology should yield unknown, got %s", got)
	}
}
