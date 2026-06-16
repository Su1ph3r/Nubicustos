package aws

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/fedmap"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(crossCloudFederation{}) }

// crossCloudFederation flags IAM roles whose trust policy federates an OIDC
// issuer belonging to a different cloud (Azure AD/Entra or Google Cloud). A
// workload in that other cloud can mint a token its issuer signs and assume the
// AWS role, inheriting its permissions: a trust edge that crosses a cloud
// boundary. Single-cloud scanners report the OIDC trust generically; naming the
// peer cloud makes the cross-cloud blast radius explicit.
type crossCloudFederation struct{}

func (crossCloudFederation) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:          "aws_cross_cloud_federation",
		Title:       "IAM role is assumable from another cloud via OIDC federation",
		Provider:    "aws",
		Service:     "iam",
		Severity:    findings.SeverityHigh,
		Rationale:   "An IAM role that federates an Azure or Google Cloud OIDC issuer can be assumed by a workload in that cloud. The trust now spans two clouds: a compromise or misconfiguration on the other side reaches into this AWS account, and the relationship is invisible to a scanner that only looks at one provider.",
		Impact:      "A workload (or attacker foothold) in the peer cloud that satisfies the trust policy can assume the role and act with its AWS permissions.",
		Remediation: "Confirm the cross-cloud trust is intended; constrain the trust policy with a StringEquals condition on the issuer's :sub (and :aud) so only the exact external workload can assume the role, and scope the role's permissions to least privilege.",
		References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html"},
	}
}

func (c crossCloudFederation) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, role := range st.AWS.IAM.Roles {
		for _, peer := range crossCloudPeers(role) {
			res := findings.Resource{
				ID: "role/" + role.Name, Name: role.Name, Type: "aws_iam_role", Provider: "aws", ARN: role.ARN,
			}
			desc := fmt.Sprintf("IAM role %q federates the %s OIDC issuer %q, so a workload in %s that satisfies the trust policy can assume this role and act with its AWS permissions.",
				role.Name, peer.cloud.Label(), peer.issuer, peer.cloud.Label())
			poc := fmt.Sprintf("aws iam get-role --role-name %s --query Role.AssumeRolePolicyDocument", role.Name)
			out = append(out, findings.New(c.Spec(), res, desc, poc, now))
		}
	}
	return out, nil
}

// crossCloudPeer is one cross-cloud federation a role's trust policy admits.
type crossCloudPeer struct {
	cloud  fedmap.Cloud
	issuer string
}

// crossCloudPeers returns the distinct cross-cloud OIDC federations in a role's
// trust policy. SAML providers are skipped: their ARN carries an admin-chosen
// name, not an issuer host, so the peer cloud cannot be positively attributed.
func crossCloudPeers(role state.IAMRole) []crossCloudPeer {
	seen := map[string]struct{}{}
	var out []crossCloudPeer
	for _, stmt := range role.TrustPolicy.Statements {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		for _, fed := range stmt.Federated {
			issuer := fedmap.IssuerFromOIDCProviderARN(fed)
			if issuer == "" {
				continue // not an OIDC provider (e.g. SAML); issuer host unknown
			}
			peer := fedmap.Classify(issuer)
			if !fedmap.CrossCloud(fedmap.AWS, peer) {
				continue
			}
			key := string(peer) + "|" + issuer
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, crossCloudPeer{cloud: peer, issuer: issuer})
		}
	}
	return out
}
