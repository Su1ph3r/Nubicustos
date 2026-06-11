package aws

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/portspec"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// sensitivePorts is the shared sensitive-port catalog. Exposure of any of these
// to the internet is treated as High severity.
var sensitivePorts = portspec.Sensitive

func init() {
	engine.RegisterCheck(ec2OpenIngress{})
	engine.RegisterCheck(ec2IMDSv2{})
	engine.RegisterCheck(ec2PublicIP{})
	engine.RegisterCheck(ec2EBSUnencrypted{})
	engine.RegisterCheck(ec2EBSDefaultEncryption{})
}

func regionalResource(account, region, id, rtype, arn string) findings.Resource {
	return findings.Resource{
		ID: id, Name: id, Type: rtype, Provider: "aws",
		Account: account, Region: region, ARN: arn,
	}
}

// --- open security-group ingress -------------------------------------------

type ec2OpenIngress struct{}

func (ec2OpenIngress) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ec2_sg_open_ingress", Title: "Security group exposes sensitive ports to the internet",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityHigh,
		Rationale:   "Administrative and database ports open to 0.0.0.0/0 are directly reachable by any host on the internet.",
		Impact:      "Attackers can brute-force, exploit, or directly connect to the exposed service without first gaining a foothold.",
		Remediation: "Restrict the ingress rule to specific trusted CIDRs or move access behind a bastion/VPN: aws ec2 revoke-security-group-ingress ...",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "5.2"}},
	}
}

func (c ec2OpenIngress) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for _, sg := range st.AWS.SecurityGroups {
		labels := exposedSensitive(sg)
		if len(labels) == 0 {
			continue
		}
		items = append(items, findings.Affected{
			Type:   "sg_rule",
			ID:     sg.ID,
			Region: sg.Region,
			Detail: fmt.Sprintf("%s exposes %s", sg.Name, strings.Join(labels, ", ")),
		})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("%d security group(s) expose sensitive ports to the internet (0.0.0.0/0 or ::/0).", len(items))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}

// exposedSensitive returns labels for the sensitive ports a security group
// exposes to the world (deduped, sorted).
func exposedSensitive(sg state.SecurityGroup) []string {
	set := map[string]struct{}{}
	for _, r := range sg.Ingress {
		if !r.OpenV4 && !r.OpenV6 {
			continue
		}
		if isAllPorts(r) {
			set["all ports"] = struct{}{}
			continue
		}
		for port, label := range sensitivePorts {
			if port >= r.FromPort && port <= r.ToPort {
				set[fmt.Sprintf("%s (%d)", label, port)] = struct{}{}
			}
		}
	}
	labels := make([]string, 0, len(set))
	for l := range set {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	return labels
}

// isAllPorts reports whether a rule covers every port (all protocols or 0-65535).
func isAllPorts(r state.IngressRule) bool {
	if r.Protocol == "-1" {
		return true
	}
	return r.FromPort == 0 && r.ToPort == 65535
}

// --- IMDSv2 -----------------------------------------------------------------

type ec2IMDSv2 struct{}

func (ec2IMDSv2) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ec2_imdsv2_not_enforced", Title: "EC2 instance does not enforce IMDSv2",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityMedium,
		Rationale:   "IMDSv1 allows credential theft via SSRF; IMDSv2 requires a session token that SSRF cannot easily obtain.",
		Impact:      "An SSRF or proxy flaw on the instance can read its IAM role credentials from the metadata service.",
		Remediation: "Require IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "5.6"}},
	}
}

func (c ec2IMDSv2) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, inst := range st.AWS.Instances {
		if inst.IMDSv2Required {
			continue
		}
		res := regionalResource(st.AWS.Account, inst.Region, inst.ID, "aws_instance", "")
		desc := fmt.Sprintf("Instance %s in %s does not require IMDSv2 (HttpTokens != required).", inst.ID, inst.Region)
		poc := fmt.Sprintf("aws ec2 describe-instances --instance-ids %s --region %s --query 'Reservations[].Instances[].MetadataOptions'", inst.ID, inst.Region)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// --- public IP --------------------------------------------------------------

type ec2PublicIP struct{}

func (ec2PublicIP) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ec2_instance_public_ip", Title: "EC2 instance has a public IP address",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityLow,
		Rationale:   "A public IP places the instance directly on the internet attack surface; combined with open ports it is exploitable.",
		Impact:      "The instance is reachable from the internet and exposed to scanning and direct attack.",
		Remediation: "Place the instance in a private subnet behind a NAT/ALB if public reachability is not required.",
	}
}

func (c ec2PublicIP) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, inst := range st.AWS.Instances {
		if inst.PublicIP == "" {
			continue
		}
		res := regionalResource(st.AWS.Account, inst.Region, inst.ID, "aws_instance", "")
		desc := fmt.Sprintf("Instance %s in %s has public IP %s.", inst.ID, inst.Region, inst.PublicIP)
		poc := fmt.Sprintf("aws ec2 describe-instances --instance-ids %s --region %s --query 'Reservations[].Instances[].PublicIpAddress'", inst.ID, inst.Region)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// --- EBS volume encryption --------------------------------------------------

type ec2EBSUnencrypted struct{}

func (ec2EBSUnencrypted) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ec2_ebs_unencrypted", Title: "EBS volume is not encrypted",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityMedium,
		Rationale:   "Unencrypted volumes expose data at rest if a snapshot or the underlying storage is accessed.",
		Impact:      "Data on the volume (and its snapshots) is readable without an encryption key barrier.",
		Remediation: "Recreate the volume from an encrypted snapshot, or enable EBS encryption by default for new volumes.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.2.1"}},
	}
}

func (c ec2EBSUnencrypted) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, v := range st.AWS.Volumes {
		if v.Encrypted {
			continue
		}
		res := regionalResource(st.AWS.Account, v.Region, v.ID, "aws_ebs_volume", "")
		desc := fmt.Sprintf("EBS volume %s in %s is not encrypted at rest.", v.ID, v.Region)
		poc := fmt.Sprintf("aws ec2 describe-volumes --volume-ids %s --region %s --query 'Volumes[].Encrypted'", v.ID, v.Region)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// --- EBS default encryption -------------------------------------------------

type ec2EBSDefaultEncryption struct{}

func (ec2EBSDefaultEncryption) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_ec2_ebs_default_encryption_disabled", Title: "EBS default encryption is disabled in a region",
		Provider: "aws", Service: "ec2", Severity: findings.SeverityMedium,
		Rationale:   "Without default encryption, newly created volumes can silently be unencrypted.",
		Impact:      "Future volumes default to unencrypted, accumulating data-at-rest exposure over time.",
		Remediation: "Enable it per region: aws ec2 enable-ebs-encryption-by-default --region <region>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "2.2.1"}},
	}
}

func (c ec2EBSDefaultEncryption) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	var items []findings.Affected
	for region, enabled := range st.AWS.EBSEncryptionByDefault {
		if enabled {
			continue
		}
		items = append(items, findings.Affected{Type: "region", Region: region})
	}
	if len(items) == 0 {
		return nil, nil
	}
	sortAffected(items)
	scope := accountResource(st.AWS.Account)
	desc := fmt.Sprintf("EBS encryption by default is disabled in %d of %d scanned region(s).",
		len(items), len(st.AWS.EBSEncryptionByDefault))
	return []findings.Finding{findings.NewAggregate(c.Spec(), scope, desc, items, time.Now().UTC())}, nil
}
