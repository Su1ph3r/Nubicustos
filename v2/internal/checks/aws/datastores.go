package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(efsUnencrypted{})
	engine.RegisterCheck(elasticacheAtRest{})
	engine.RegisterCheck(elasticacheInTransit{})
	engine.RegisterCheck(dynamoDBNoPITR{})
}

type efsUnencrypted struct{}

func (efsUnencrypted) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_efs_unencrypted", Title: "EFS file system is not encrypted at rest",
		Provider: "aws", Service: "efs", Severity: findings.SeverityMedium,
		Rationale:   "An unencrypted EFS file system stores data in plaintext at rest, so disk or snapshot compromise exposes it directly. Encryption can only be set at creation.",
		Impact:      "File-system data is readable if the underlying storage is accessed.",
		Remediation: "Recreate the file system with encryption enabled and migrate data: aws efs create-file-system --encrypted",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c efsUnencrypted) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, f := range st.AWS.EFS {
		if f.Encrypted {
			continue
		}
		res := findings.Resource{ID: f.ID, Name: f.ID, Type: "aws_efs_file_system", Provider: "aws", Region: f.Region}
		desc := fmt.Sprintf("EFS file system %q (%s) is not encrypted at rest.", f.ID, f.Region)
		poc := fmt.Sprintf("aws efs describe-file-systems --file-system-id %s --region %s --query 'FileSystems[].Encrypted'", f.ID, f.Region)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

type elasticacheAtRest struct{}

func (elasticacheAtRest) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_elasticache_at_rest_encryption_disabled", Title: "ElastiCache replication group is not encrypted at rest",
		Provider: "aws", Service: "elasticache", Severity: findings.SeverityMedium,
		Rationale:   "Without at-rest encryption, ElastiCache (Redis) data and backups are stored in plaintext, exposing cached data if the storage is accessed.",
		Impact:      "Cached data (which often includes sensitive session/PII material) is readable at rest.",
		Remediation: "Enable at-rest encryption (set at creation): recreate the replication group with --at-rest-encryption-enabled.",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c elasticacheAtRest) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return elasticacheFindings(st, c.Spec(), func(g state.ElasticacheGroup) bool { return g.AtRestEncrypted }, "is not encrypted at rest")
}

type elasticacheInTransit struct{}

func (elasticacheInTransit) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_elasticache_in_transit_encryption_disabled", Title: "ElastiCache replication group does not encrypt in transit",
		Provider: "aws", Service: "elasticache", Severity: findings.SeverityMedium,
		Rationale:   "Without in-transit encryption, ElastiCache (Redis) traffic — including any AUTH token and cached data — travels in plaintext and can be intercepted on the network path.",
		Impact:      "Cached data and credentials in transit can be observed by an attacker on the network.",
		Remediation: "Enable in-transit encryption (set at creation): recreate the replication group with --transit-encryption-enabled.",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c elasticacheInTransit) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return elasticacheFindings(st, c.Spec(), func(g state.ElasticacheGroup) bool { return g.InTransitEncrypted }, "does not encrypt traffic in transit")
}

// elasticacheFindings emits a finding per replication group failing the ok
// predicate, shared by the at-rest and in-transit checks.
func elasticacheFindings(st *state.State, spec findings.CheckSpec, ok func(state.ElasticacheGroup) bool, phrase string) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, g := range st.AWS.Elasticache {
		if ok(g) {
			continue
		}
		res := findings.Resource{ID: g.ID, Name: g.ID, Type: "aws_elasticache_replication_group", Provider: "aws", Region: g.Region}
		desc := fmt.Sprintf("ElastiCache replication group %q (%s) %s.", g.ID, g.Region, phrase)
		poc := fmt.Sprintf("aws elasticache describe-replication-groups --replication-group-id %s --region %s", g.ID, g.Region)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

type dynamoDBNoPITR struct{}

func (dynamoDBNoPITR) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_dynamodb_pitr_disabled", Title: "DynamoDB table has point-in-time recovery disabled",
		Provider: "aws", Service: "dynamodb", Severity: findings.SeverityLow,
		Rationale:   "Without point-in-time recovery there is no continuous backup, so accidental deletes/overwrites or a ransomware event cannot be rolled back to a prior state.",
		Impact:      "Data loss from corruption, deletion, or malicious modification is unrecoverable.",
		Remediation: "aws dynamodb update-continuous-backups --table-name <name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "REL-Backup"}},
	}
}

func (c dynamoDBNoPITR) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, t := range st.AWS.DynamoDB {
		if t.PITREnabled {
			continue
		}
		res := findings.Resource{ID: t.Name, Name: t.Name, Type: "aws_dynamodb_table", Provider: "aws", Region: t.Region}
		desc := fmt.Sprintf("DynamoDB table %q (%s) has point-in-time recovery disabled.", t.Name, t.Region)
		poc := fmt.Sprintf("aws dynamodb describe-continuous-backups --table-name %s --region %s", t.Name, t.Region)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
