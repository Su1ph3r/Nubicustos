package aws

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func oidcTrust(providerARNs ...string) state.PolicyDocument {
	return state.PolicyDocument{Statements: []state.PolicyStatement{
		{Effect: "Allow", Federated: providerARNs},
	}}
}

func TestCrossCloudFederation(t *testing.T) {
	st := state.New()
	st.SetIAM(state.IAMState{Roles: []state.IAMRole{
		{
			Name: "from-azure", ARN: "arn:aws:iam::111122223333:role/from-azure",
			TrustPolicy: oidcTrust("arn:aws:iam::111122223333:oidc-provider/sts.windows.net/72f988bf-tenant/"),
		},
		{
			Name: "from-gcp", ARN: "arn:aws:iam::111122223333:role/from-gcp",
			TrustPolicy: oidcTrust("arn:aws:iam::111122223333:oidc-provider/accounts.google.com"),
		},
		{
			Name: "eks-internal", ARN: "arn:aws:iam::111122223333:role/eks-internal",
			TrustPolicy: oidcTrust("arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"),
		},
		{
			Name: "github-ci", ARN: "arn:aws:iam::111122223333:role/github-ci",
			TrustPolicy: oidcTrust("arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"),
		},
	}})

	fs, err := crossCloudFederation{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	// Only the Azure- and GCP-federated roles are cross-cloud; EKS (same-cloud)
	// and GitHub (CI, not a cloud peer) are not flagged.
	if len(fs) != 2 {
		t.Fatalf("expected 2 cross-cloud findings, got %d: %+v", len(fs), fs)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Resource.ID] = f.Description
	}
	if _, ok := got["role/from-azure"]; !ok {
		t.Error("expected a finding on role/from-azure")
	}
	if !strings.Contains(got["role/from-azure"], "Azure") {
		t.Errorf("azure finding should name the peer cloud: %q", got["role/from-azure"])
	}
	if !strings.Contains(got["role/from-gcp"], "Google Cloud") {
		t.Errorf("gcp finding should name the peer cloud: %q", got["role/from-gcp"])
	}
}

func TestCrossCloudFederationNoIAM(t *testing.T) {
	st := state.New() // IAM not collected
	if fs, _ := (crossCloudFederation{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("uncollected IAM should yield no findings, got %d", len(fs))
	}
}

func TestCrossCloudFederationDedupesIssuer(t *testing.T) {
	st := state.New()
	st.SetIAM(state.IAMState{Roles: []state.IAMRole{{
		Name: "dup", ARN: "arn:aws:iam::111122223333:role/dup",
		TrustPolicy: state.PolicyDocument{Statements: []state.PolicyStatement{
			{Effect: "Allow", Federated: []string{"arn:aws:iam::1:oidc-provider/sts.windows.net/t/"}},
			{Effect: "Allow", Federated: []string{"arn:aws:iam::1:oidc-provider/sts.windows.net/t/"}},
		}},
	}}})
	if fs, _ := (crossCloudFederation{}).Evaluate(nil, st); len(fs) != 1 {
		t.Fatalf("the same issuer twice should produce one finding, got %d", len(fs))
	}
}
