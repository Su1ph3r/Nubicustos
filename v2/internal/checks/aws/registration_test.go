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
	// + Lambda(2) + SNS(1) + SQS(1) + Redshift(2) + ECR(2) + CloudWatch monitoring(1)
	// + EFS(1) + ElastiCache(2) + DynamoDB(1) + classic-ELB(1)
	// + exposed-secret(1) + IAM trust/privilege umbrella(1) = 49.
	// Azure catalog: storage(5) + NSG(1) + key vault(3) + app service(3)
	// + SQL(3) + Cosmos(2) + Defender(1) + RBAC(1) + Entra(3) + Monitor(1)
	// + rdbms(1) + VM(1) + Redis(1) + exposed-secret(1) = 27.
	// GCP catalog: storage(3) + firewall(1) + IAM(2) + exposed-secret(1)
	// + Cloud SQL(4) + compute(3) + KMS(2) + GKE(3) + logging(1) + trust(1)
	// + monitoring(1) = 22.
	// K8s catalog: pods(4) + RBAC(2) + exposed-secret(1) = 7.
	// Plus the policy-as-code rules umbrella check = 1. Total = 106.
	const wantChecks = 106
	if len(checks) != wantChecks {
		t.Errorf("registered checks = %d, want %d", len(checks), wantChecks)
	}

	// Collectors: AWS s3, iam, ec2, rds, cloudtrail, kms, config, guardduty,
	// vpc, snapshots, secretsmanager, elbv2, acm, route53, lambda, messaging,
	// redshift, ecr, cloudwatch, datastores, elb-classic, secrets-scan = 22;
	// Azure storage, nsg, keyvault, appservice, sql, cosmos, defender, rbac,
	// entra, network, monitor, rdbms, vm, redis, secrets-scan = 15; GCP storage, firewall, iam,
	// secrets-scan, cloudsql, compute, kms, gke, monitoring = 9; K8s pods, rbac,
	// secrets-scan = 3. Total = 49.
	const wantCollectors = 49
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
