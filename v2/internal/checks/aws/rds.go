package aws

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(rdsPublic{})
	engine.RegisterCheck(rdsUnencrypted{})
	engine.RegisterCheck(rdsBackupDisabled{})
	engine.RegisterCheck(rdsDeletionProtection{})
}

func rdsResource(account, region, id string) findings.Resource {
	return regionalResource(account, region, id, "aws_db_instance",
		fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, account, id))
}

type rdsPublic struct{}

func (rdsPublic) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_rds_public", Title: "RDS instance is publicly accessible",
		Provider: "aws", Service: "rds", Severity: findings.SeverityHigh,
		Rationale:   "A publicly accessible database is reachable from the internet, exposing it to direct attack and brute force.",
		Impact:      "Attackers can attempt to connect directly to the database from anywhere on the internet.",
		Remediation: "Set PubliclyAccessible=false: aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.3.3"}},
	}
}

func (c rdsPublic) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return evalRDS(st, c.Spec(), func(db state.RDSInstance) (bool, string, string) {
		if !db.Public {
			return false, "", ""
		}
		return true,
			fmt.Sprintf("RDS instance %s (%s) in %s is publicly accessible.", db.ID, db.Engine, db.Region),
			fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].PubliclyAccessible'", db.ID, db.Region)
	})
}

type rdsUnencrypted struct{}

func (rdsUnencrypted) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_rds_unencrypted", Title: "RDS instance storage is not encrypted",
		Provider: "aws", Service: "rds", Severity: findings.SeverityMedium,
		Rationale:   "Unencrypted RDS storage exposes data at rest if the underlying storage or a snapshot is accessed.",
		Impact:      "Database contents and snapshots are readable without an encryption-key barrier.",
		Remediation: "Encryption cannot be enabled in place; restore from an encrypted snapshot copy and cut over.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.3.1"}},
	}
}

func (c rdsUnencrypted) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return evalRDS(st, c.Spec(), func(db state.RDSInstance) (bool, string, string) {
		if db.Encrypted {
			return false, "", ""
		}
		return true,
			fmt.Sprintf("RDS instance %s (%s) in %s is not encrypted at rest.", db.ID, db.Engine, db.Region),
			fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].StorageEncrypted'", db.ID, db.Region)
	})
}

type rdsBackupDisabled struct{}

func (rdsBackupDisabled) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_rds_backup_disabled", Title: "RDS instance has automated backups disabled",
		Provider: "aws", Service: "rds", Severity: findings.SeverityMedium,
		Rationale:   "A zero-day backup retention means no point-in-time recovery; data loss or ransomware cannot be rolled back.",
		Impact:      "There is no recovery path from accidental deletion, corruption, or ransomware.",
		Remediation: "Set a retention period: aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7 --apply-immediately",
	}
}

func (c rdsBackupDisabled) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return evalRDS(st, c.Spec(), func(db state.RDSInstance) (bool, string, string) {
		if db.BackupRetention > 0 {
			return false, "", ""
		}
		return true,
			fmt.Sprintf("RDS instance %s (%s) in %s has automated backups disabled (retention 0).", db.ID, db.Engine, db.Region),
			fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].BackupRetentionPeriod'", db.ID, db.Region)
	})
}

type rdsDeletionProtection struct{}

func (rdsDeletionProtection) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_rds_deletion_protection_disabled", Title: "RDS instance has deletion protection disabled",
		Provider: "aws", Service: "rds", Severity: findings.SeverityLow,
		Rationale:   "Without deletion protection a database can be destroyed by a single accidental or malicious API call.",
		Impact:      "The instance can be deleted instantly, causing data loss and outage.",
		Remediation: "Enable it: aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection --apply-immediately",
	}
}

func (c rdsDeletionProtection) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	return evalRDS(st, c.Spec(), func(db state.RDSInstance) (bool, string, string) {
		if db.DeletionProtection {
			return false, "", ""
		}
		return true,
			fmt.Sprintf("RDS instance %s (%s) in %s has deletion protection disabled.", db.ID, db.Engine, db.Region),
			fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --region %s --query 'DBInstances[].DeletionProtection'", db.ID, db.Region)
	})
}

// evalRDS applies a per-instance predicate and builds findings, removing the
// boilerplate shared by the RDS checks.
func evalRDS(st *state.State, spec findings.CheckSpec, test func(state.RDSInstance) (bool, string, string)) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, db := range st.AWS.RDSInstances {
		flag, desc, poc := test(db)
		if !flag {
			continue
		}
		res := rdsResource(st.AWS.Account, db.Region, db.ID)
		if db.Endpoint != "" && db.Port > 0 {
			res.Endpoint = net.JoinHostPort(db.Endpoint, strconv.Itoa(db.Port))
		}
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}
