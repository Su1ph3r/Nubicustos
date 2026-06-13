package aws_test

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/engine"

	// Importing these packages triggers init-time registration of the
	// collectors and checks into the engine registry. This is the full-catalog
	// guard, so it imports every provider's checks and collectors.
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/k8s"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/rules"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/k8s"
)

// TestAllChecksUnique guards against duplicate check IDs (a copy-paste hazard as
// the catalog grows) and asserts the Phase-1 catalog is fully wired.
func TestAllChecksUnique(t *testing.T) {
	checks := engine.Checks()

	seen := map[string]bool{}
	for _, c := range checks {
		id := c.Spec().ID
		if id == "" {
			t.Errorf("check with empty ID: %T", c)
		}
		if seen[id] {
			t.Errorf("duplicate check ID: %s", id)
		}
		seen[id] = true
	}

	// AWS catalog: S3(1) + IAM(6) + EC2(5) + RDS(4) + CloudTrail(3)
	// + KMS(1) + Config(1) + GuardDuty(1) + VPC(1) + exposure(3)
	// + SecretsManager(1) + ELB(3) + ACM(2) + Route53 dangling(1)
	// + IAM trust/privilege umbrella(1) = 34.
	// Azure catalog: storage(3) + NSG(1) + key vault(3) = 7.
	// GCP catalog: storage(3) + firewall(1) + IAM(2) = 6.
	// K8s catalog: pods(4) + RBAC(2) = 6.
	// Plus the policy-as-code rules umbrella check = 1. Total = 54.
	const wantChecks = 54
	if len(checks) != wantChecks {
		t.Errorf("registered checks = %d, want %d", len(checks), wantChecks)
	}

	// Collectors: AWS s3, iam, ec2, rds, cloudtrail, kms, config, guardduty,
	// vpc, snapshots, secretsmanager, elbv2, acm, route53 = 14; Azure storage,
	// nsg, keyvault = 3; GCP storage, firewall, iam = 3; K8s pods, rbac = 2.
	// Total = 22.
	const wantCollectors = 22
	if got := len(engine.Collectors()); got != wantCollectors {
		t.Errorf("registered collectors = %d, want %d", got, wantCollectors)
	}
}

// TestChecksHaveMetadata ensures every check carries the reporting metadata that
// makes a finding self-contained.
func TestChecksHaveMetadata(t *testing.T) {
	for _, c := range engine.Checks() {
		s := c.Spec()
		if s.Title == "" || s.Provider == "" || s.Service == "" {
			t.Errorf("check %s missing core metadata: %+v", s.ID, s)
		}
		if s.Severity == "" {
			t.Errorf("check %s missing severity", s.ID)
		}
		if s.Remediation == "" {
			t.Errorf("check %s missing remediation guidance", s.ID)
		}
	}
}
