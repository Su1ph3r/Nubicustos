package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(redshiftPublic{})
	engine.RegisterCheck(redshiftUnencrypted{})
}

func redshiftResource(c state.RedshiftCluster) findings.Resource {
	return findings.Resource{
		ID: c.ID, Name: c.ID, Type: "aws_redshift_cluster", Provider: "aws", Region: c.Region,
	}
}

type redshiftPublic struct{}

func (redshiftPublic) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_redshift_publicly_accessible", Title: "Redshift cluster is publicly accessible",
		Provider: "aws", Service: "redshift", Severity: findings.SeverityHigh,
		Rationale:   "A publicly-accessible Redshift cluster is reachable from the internet, exposing the data-warehouse endpoint to credential and exploit attacks.",
		Impact:      "External hosts can reach the cluster endpoint directly.",
		Remediation: "Disable public accessibility and use private networking: aws redshift modify-cluster --cluster-identifier <id> --no-publicly-accessible",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-Network"}},
	}
}

func (c redshiftPublic) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cl := range st.AWS.Redshift {
		if !cl.Public {
			continue
		}
		desc := fmt.Sprintf("Redshift cluster %q (%s) is publicly accessible.", cl.ID, cl.Region)
		poc := fmt.Sprintf("aws redshift describe-clusters --cluster-identifier %s --region %s --query 'Clusters[].PubliclyAccessible'", cl.ID, cl.Region)
		out = append(out, findings.New(c.Spec(), redshiftResource(cl), desc, poc, now))
	}
	return out, nil
}

type redshiftUnencrypted struct{}

func (redshiftUnencrypted) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_redshift_unencrypted", Title: "Redshift cluster is not encrypted at rest",
		Provider: "aws", Service: "redshift", Severity: findings.SeverityMedium,
		Rationale:   "An unencrypted Redshift cluster stores warehouse data in plaintext at rest, so disk or snapshot compromise exposes it directly.",
		Impact:      "Data at rest (and its snapshots) is readable if the underlying storage is accessed.",
		Remediation: "Enable encryption (requires a cluster modify/restore): aws redshift modify-cluster --cluster-identifier <id> --encrypted",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-DataProtection"}},
	}
}

func (c redshiftUnencrypted) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, cl := range st.AWS.Redshift {
		if cl.Encrypted {
			continue
		}
		desc := fmt.Sprintf("Redshift cluster %q (%s) is not encrypted at rest.", cl.ID, cl.Region)
		poc := fmt.Sprintf("aws redshift describe-clusters --cluster-identifier %s --region %s --query 'Clusters[].Encrypted'", cl.ID, cl.Region)
		out = append(out, findings.New(c.Spec(), redshiftResource(cl), desc, poc, now))
	}
	return out, nil
}
