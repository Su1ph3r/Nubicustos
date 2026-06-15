package compliance

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		spec findings.CheckSpec
		want Category
	}{
		{findings.CheckSpec{ID: "aws_root_mfa_disabled", Service: "iam", Title: "Root MFA disabled"}, CatMFA},
		{findings.CheckSpec{ID: "aws_exposed_secret", Service: "secrets", Title: "Secret in control plane"}, CatSecrets},
		{findings.CheckSpec{ID: "azure_storage_not_https_only", Service: "storage", Title: "No HTTPS"}, CatEncryptionInTransit},
		{findings.CheckSpec{ID: "aws_redshift_unencrypted", Service: "redshift", Title: "Not encrypted at rest"}, CatEncryptionAtRest},
		{findings.CheckSpec{ID: "aws_s3_public_access", Service: "s3", Title: "Public bucket"}, CatPublicExposure},
		{findings.CheckSpec{ID: "aws_sg_open_ingress", Service: "ec2", Title: "Security group open ingress"}, CatPublicExposure},
		{findings.CheckSpec{ID: "azure_nsg_open_ingress", Service: "network", Title: "NSG sensitive ports"}, CatPublicExposure},
		{findings.CheckSpec{ID: "aws_cloudtrail_no_logging", Service: "cloudtrail", Title: "No trail logging"}, CatLogging},
		{findings.CheckSpec{ID: "aws_redshift_publicly_accessible", Service: "redshift", Title: "Publicly accessible"}, CatPublicExposure},
		{findings.CheckSpec{ID: "azure_rbac_custom_role_wildcard", Service: "rbac", Title: "Wildcard role"}, CatAccessControl},
	}
	for _, c := range cases {
		if got := Classify(c.spec); got != c.want {
			t.Errorf("Classify(%s) = %s, want %s", c.spec.ID, got, c.want)
		}
	}
}

func TestBuildCoverageAndFindings(t *testing.T) {
	specs := []findings.CheckSpec{
		{ID: "aws_redshift_unencrypted", Service: "redshift", Title: "Not encrypted at rest"},
		{ID: "aws_s3_public_access", Service: "s3", Title: "Public bucket"},
	}
	// One open finding against the encryption check.
	fs := []findings.Finding{{CheckID: "aws_redshift_unencrypted"}}

	rep := Build(FrameworkNIST, specs, fs)
	if rep.Covered < 2 {
		t.Fatalf("expected at least 2 controls covered, got %d", rep.Covered)
	}
	var sawFail bool
	for _, c := range rep.Controls {
		if c.Control.ID == "SC-28" { // encryption-at-rest → NIST SC-28
			if c.Status != "fail" || c.OpenFindings != 1 {
				t.Errorf("SC-28 should be failing with 1 finding, got %+v", c)
			}
			sawFail = true
		}
	}
	if !sawFail {
		t.Error("expected the encryption-at-rest control (SC-28) in the report")
	}
}

func TestValidFramework(t *testing.T) {
	for _, ok := range []string{"soc2", "pci", "nist"} {
		if !ValidFramework(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	if ValidFramework("hipaa") {
		t.Error("hipaa is not supported and should be invalid")
	}
}
