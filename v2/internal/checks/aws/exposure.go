package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(vpcFlowLogs{})
	engine.RegisterCheck(publicEBSSnapshots{})
	engine.RegisterCheck(publicAMIs{})
	engine.RegisterCheck(publicRDSSnapshots{})
}

// refsToAffected converts collected resource references into affected items.
func refsToAffected(refs []state.ResourceRef, typ string) []findings.Affected {
	items := make([]findings.Affected, 0, len(refs))
	for _, r := range refs {
		items = append(items, findings.Affected{Type: typ, ID: r.ID, Region: r.Region, ARN: r.ARN})
	}
	return items
}

// --- VPC flow logs ----------------------------------------------------------

type vpcFlowLogs struct{}

func (vpcFlowLogs) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_vpc_flow_logs_disabled", Title: "VPC does not have flow logs enabled",
		Provider: "aws", Service: "vpc", Severity: findings.SeverityMedium,
		Rationale:   "VPC Flow Logs capture network traffic metadata needed to investigate intrusions and detect exfiltration.",
		Impact:      "Without flow logs there is no network-level record to investigate lateral movement or data exfiltration.",
		Remediation: "Enable flow logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs ...",
		PoC:         "aws ec2 describe-flow-logs --filter Name=resource-id,Values=<vpc-id>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "3.9"}},
	}
}

func (c vpcFlowLogs) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for _, v := range st.AWS.VPCs {
		if v.HasFlowLog {
			continue
		}
		items = append(items, findings.Affected{Type: "vpc", ID: v.ID, Region: v.Region})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d VPC(s) do not have flow logs enabled.", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}

// --- public EBS snapshots ---------------------------------------------------

type publicEBSSnapshots struct{}

func (publicEBSSnapshots) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ebs_snapshot_public", Title: "EBS snapshot is publicly shared",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityHigh,
		Rationale:   "A public EBS snapshot can be copied and mounted by anyone, exposing all data on the original volume.",
		Impact:      "Any AWS user worldwide can restore the snapshot and read its data.",
		Remediation: "Make it private: aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission --operation-type remove --group-names all",
		PoC:         "aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.2.2"}},
	}
}

func (c publicEBSSnapshots) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || len(st.AWS.PublicEBSSnapshots) == 0 {
		return nil, nil
	}
	items := refsToAffected(st.AWS.PublicEBSSnapshots, "ebs_snapshot")
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d EBS snapshot(s) are publicly shared (restorable by all).", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}

// --- public AMIs ------------------------------------------------------------

type publicAMIs struct{}

func (publicAMIs) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ami_public", Title: "AMI is publicly shared",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityHigh,
		Rationale:   "A public AMI can be launched by anyone and often embeds secrets, keys, or proprietary software in its image.",
		Impact:      "Any AWS user can launch the image and inspect its filesystem for embedded credentials or data.",
		Remediation: "Make it private: aws ec2 modify-image-attribute --image-id <id> --launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'",
		PoC:         "aws ec2 describe-images --owners self --query 'Images[?Public==`true`]'",
	}
}

func (c publicAMIs) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || len(st.AWS.PublicAMIs) == 0 {
		return nil, nil
	}
	items := refsToAffected(st.AWS.PublicAMIs, "ami")
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d AMI(s) are publicly shared.", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}

// --- public RDS snapshots ---------------------------------------------------

type publicRDSSnapshots struct{}

func (publicRDSSnapshots) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_rds_snapshot_public", Title: "RDS snapshot is publicly shared",
		Provider: "aws", Service: "rds", Severity: findings.SeverityHigh,
		Rationale:   "A public RDS snapshot can be restored by any AWS account, exposing the entire database contents.",
		Impact:      "Any AWS user worldwide can restore the snapshot into their account and read the database.",
		Remediation: "Make it private: aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all",
		PoC:         "aws rds describe-db-snapshot-attributes --db-snapshot-identifier <id>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.3.2"}},
	}
}

func (c publicRDSSnapshots) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || len(st.AWS.PublicRDSSnapshots) == 0 {
		return nil, nil
	}
	items := refsToAffected(st.AWS.PublicRDSSnapshots, "rds_snapshot")
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d RDS snapshot(s) are publicly shared.", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}
