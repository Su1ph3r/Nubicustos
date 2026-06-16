// Package fedmap classifies an OIDC/SAML federation issuer by the cloud identity
// provider that issues its tokens, so the scanner can tell a same-cloud workload
// federation (an EKS pod assuming an IAM role) apart from a cross-cloud trust
// boundary (an Azure or GCP workload that can assume an AWS role, or vice versa).
//
// This is the join key for cross-cloud federation analysis. Single-cloud
// scanners flag "this role trusts an OIDC provider" generically; naming the
// provider's cloud turns that into "an identity in cloud B can act in cloud A,"
// a trust edge that crosses an account/tenant boundary most tools never connect.
package fedmap

import "strings"

// Cloud identifies the identity provider behind a federation issuer.
type Cloud string

const (
	AWS    Cloud = "aws"
	Azure  Cloud = "azure"
	GCP    Cloud = "gcp"
	GitHub Cloud = "github" // a common CI issuer, not a cloud peer
	Other  Cloud = "other"  // GitLab, generic OIDC, or unrecognized
)

// Label renders a human name for the issuing provider.
func (c Cloud) Label() string {
	switch c {
	case AWS:
		return "AWS"
	case Azure:
		return "Azure AD / Entra"
	case GCP:
		return "Google Cloud"
	case GitHub:
		return "GitHub Actions"
	default:
		return "an external issuer"
	}
}

// issuerSignatures maps a host/substring to its cloud. Order matters only in
// that the first match wins; the substrings are disjoint enough in practice.
var issuerSignatures = []struct {
	needle string
	cloud  Cloud
}{
	// Azure AD / Entra token issuers.
	{"sts.windows.net", Azure},
	{"login.microsoftonline.com", Azure},
	{"login.microsoftonline.us", Azure},
	{"login.windows.net", Azure},
	{"login.partner.microsoftonline.cn", Azure},
	// Google Cloud issuers (account tokens, GKE cluster OIDC, STS).
	{"accounts.google.com", GCP},
	{"container.googleapis.com", GCP},
	{"iam.googleapis.com", GCP},
	{"sts.googleapis.com", GCP},
	{"gserviceaccount.com", GCP},
	// AWS issuers (EKS cluster OIDC, Cognito).
	{"amazonaws.com", AWS},
	{"cognito-identity", AWS},
	// GitHub Actions OIDC (a CI provider, not a cloud peer).
	{"token.actions.githubusercontent.com", GitHub},
	{"githubusercontent.com", GitHub},
}

// Classify maps a federation issuer to its cloud. The input may be a bare host,
// a full issuer URL ("https://sts.windows.net/<tenant>/"), or an AWS OIDC
// provider ARN ("arn:aws:iam::123:oidc-provider/<host>/..."); the host is
// matched anywhere in the string, so all three forms resolve. An unrecognized
// issuer is Other (never guessed into a cloud), so cross-cloud findings never
// fire on an issuer we cannot positively attribute.
func Classify(issuer string) Cloud {
	s := strings.ToLower(strings.TrimSpace(issuer))
	if s == "" {
		return Other
	}
	for _, sig := range issuerSignatures {
		if strings.Contains(s, sig.needle) {
			return sig.cloud
		}
	}
	return Other
}

// IsCloud reports whether c is one of the three major clouds (the peers a
// cross-cloud trust can bridge), as opposed to a CI issuer or an unknown one.
func (c Cloud) IsCloud() bool {
	return c == AWS || c == Azure || c == GCP
}

// CrossCloud reports whether a federation from issuer (as seen in the scanned
// cloud `here`) crosses a cloud boundary: both ends are major clouds and they
// differ. A GitHub or unrecognized issuer is not a cross-cloud peer, and a
// same-cloud federation (here == counterparty) is normal workload identity, so
// neither trips the check.
func CrossCloud(here, counterparty Cloud) bool {
	return here.IsCloud() && counterparty.IsCloud() && here != counterparty
}

// IssuerFromOIDCProviderARN extracts the issuer host (and any path) from an AWS
// IAM OIDC-provider ARN. "arn:aws:iam::123:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X"
// yields "oidc.eks.us-east-1.amazonaws.com/id/X". Returns "" if the ARN is not
// an oidc-provider ARN (e.g. a saml-provider, whose name does not reveal an
// issuer host and so cannot be classified).
func IssuerFromOIDCProviderARN(arn string) string {
	const marker = ":oidc-provider/"
	i := strings.Index(arn, marker)
	if i < 0 {
		return ""
	}
	return arn[i+len(marker):]
}
