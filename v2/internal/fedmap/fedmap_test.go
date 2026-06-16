package fedmap

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		issuer string
		want   Cloud
	}{
		{"https://sts.windows.net/72f988bf-0000-0000-0000-000000000000/", Azure},
		{"https://login.microsoftonline.com/common/v2.0", Azure},
		{"https://accounts.google.com", GCP},
		{"https://container.googleapis.com/v1/projects/p/locations/l/clusters/c", GCP},
		{"my-pool@my-project.iam.gserviceaccount.com", GCP},
		{"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC", AWS},
		{"cognito-identity.amazonaws.com", AWS},
		{"https://token.actions.githubusercontent.com", GitHub},
		{"https://gitlab.com", Other},
		{"", Other},
		{"   ", Other},
	}
	for _, tc := range tests {
		if got := Classify(tc.issuer); got != tc.want {
			t.Errorf("Classify(%q) = %q, want %q", tc.issuer, got, tc.want)
		}
	}
}

func TestCrossCloud(t *testing.T) {
	tests := []struct {
		here, peer Cloud
		want       bool
	}{
		{AWS, Azure, true},
		{AWS, GCP, true},
		{Azure, AWS, true},
		{GCP, Azure, true},
		{AWS, AWS, false},     // same cloud: normal workload identity
		{AWS, GitHub, false},  // CI issuer, not a cloud peer
		{Azure, Other, false}, // unrecognized issuer never trips it
		{AWS, Other, false},
	}
	for _, tc := range tests {
		if got := CrossCloud(tc.here, tc.peer); got != tc.want {
			t.Errorf("CrossCloud(%q,%q) = %v, want %v", tc.here, tc.peer, got, tc.want)
		}
	}
}

func TestIssuerFromOIDCProviderARN(t *testing.T) {
	tests := []struct {
		arn, want string
	}{
		{"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X", "oidc.eks.us-east-1.amazonaws.com/id/X"},
		{"arn:aws:iam::123456789012:oidc-provider/accounts.google.com", "accounts.google.com"},
		{"arn:aws:iam::123456789012:saml-provider/AzureAD", ""}, // SAML: no issuer host
		{"arn:aws:iam::123456789012:role/foo", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := IssuerFromOIDCProviderARN(tc.arn); got != tc.want {
			t.Errorf("IssuerFromOIDCProviderARN(%q) = %q, want %q", tc.arn, got, tc.want)
		}
	}
}

func TestIsCloudAndLabel(t *testing.T) {
	if !AWS.IsCloud() || !Azure.IsCloud() || !GCP.IsCloud() {
		t.Error("the three majors must report IsCloud")
	}
	if GitHub.IsCloud() || Other.IsCloud() {
		t.Error("github/other must not report IsCloud")
	}
	if AWS.Label() == "" || Other.Label() == "" {
		t.Error("every cloud should render a label")
	}
}
