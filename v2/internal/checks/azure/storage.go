// Package azure contains native Azure posture checks. Checks read collected
// state and emit findings; they never call cloud APIs. Each check pairs a
// CheckSpec with per-resource finding generation, mirroring the AWS checks.
package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(storageBlobPublic{})
	engine.RegisterCheck(storageNotHTTPSOnly{})
	engine.RegisterCheck(storageNetworkOpen{})
	engine.RegisterCheck(storageMinTLS{})
	engine.RegisterCheck(storageSharedKeyAccess{})
}

// storageResource builds the normalized resource for a storage account.
func storageResource(a state.StorageAccount) findings.Resource {
	return findings.Resource{
		ID: a.Name, Name: a.Name, Type: "azure_storage_account", Provider: "azure",
		Account: a.Subscription, Region: a.Location,
	}
}

type storageBlobPublic struct{}

func (storageBlobPublic) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_storage_blob_public_access", Title: "Storage account allows anonymous blob access",
		Provider: "azure", Service: "storage", Severity: findings.SeverityHigh,
		Rationale:   "When a storage account permits public blob access, containers/blobs set to public can be read anonymously over the internet.",
		Impact:      "An unauthenticated attacker can read any container or blob configured for public access.",
		Remediation: "Disable account-level public access: az storage account update --name <name> --resource-group <rg> --allow-blob-public-access false",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "3.7"}},
	}
}

func (c storageBlobPublic) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.StorageAccounts {
		if !a.AllowBlobPublicAccess {
			continue
		}
		desc := fmt.Sprintf("Storage account %q (sub %s) allows anonymous blob public access.", a.Name, a.Subscription)
		poc := fmt.Sprintf("az storage account show --name %s --resource-group %s --query allowBlobPublicAccess", a.Name, a.ResourceGroup)
		out = append(out, findings.New(c.Spec(), storageResource(a), desc, poc, now))
	}
	return out, nil
}

type storageNotHTTPSOnly struct{}

func (storageNotHTTPSOnly) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_storage_not_https_only", Title: "Storage account does not enforce HTTPS-only traffic",
		Provider: "azure", Service: "storage", Severity: findings.SeverityMedium,
		Rationale:   "Without HTTPS enforcement, requests can be made over plaintext HTTP and intercepted.",
		Impact:      "Data and SAS tokens in transit can be observed or tampered with on the network path.",
		Remediation: "az storage account update --name <name> --resource-group <rg> --https-only true",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "3.1"}},
	}
}

func (c storageNotHTTPSOnly) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.StorageAccounts {
		if a.HTTPSOnly {
			continue
		}
		desc := fmt.Sprintf("Storage account %q does not enforce HTTPS-only traffic.", a.Name)
		poc := fmt.Sprintf("az storage account show --name %s --resource-group %s --query enableHttpsTrafficOnly", a.Name, a.ResourceGroup)
		out = append(out, findings.New(c.Spec(), storageResource(a), desc, poc, now))
	}
	return out, nil
}

type storageNetworkOpen struct{}

func (storageNetworkOpen) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_storage_network_default_allow", Title: "Storage account network rules default to Allow",
		Provider: "azure", Service: "storage", Severity: findings.SeverityMedium,
		Rationale:   "A network rule set whose default action is Allow exposes the account to every network, defeating private-endpoint/firewall restrictions.",
		Impact:      "The account is reachable from any network, widening the attack surface.",
		Remediation: "Set the default action to Deny and allow only required networks: az storage account update --name <name> --resource-group <rg> --default-action Deny",
	}
}

func (c storageNetworkOpen) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.StorageAccounts {
		if !a.NetworkDefaultAllow {
			continue
		}
		desc := fmt.Sprintf("Storage account %q network rule set defaults to Allow (open to all networks).", a.Name)
		poc := fmt.Sprintf("az storage account show --name %s --resource-group %s --query networkRuleSet.defaultAction", a.Name, a.ResourceGroup)
		out = append(out, findings.New(c.Spec(), storageResource(a), desc, poc, now))
	}
	return out, nil
}

type storageMinTLS struct{}

func (storageMinTLS) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_storage_min_tls", Title: "Storage account allows TLS below 1.2",
		Provider: "azure", Service: "storage", Severity: findings.SeverityMedium,
		Rationale:   "A minimum TLS version below 1.2 permits clients to negotiate deprecated, weak protocol versions with known cryptographic weaknesses.",
		Impact:      "Traffic to the account can be negotiated down to TLS 1.0/1.1, exposing data in transit to downgrade and interception attacks.",
		Remediation: "az storage account update --name <name> --resource-group <rg> --min-tls-version TLS1_2",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "3.15"}},
	}
}

func (c storageMinTLS) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.StorageAccounts {
		// An empty value means the minimum TLS version could not be determined;
		// only flag an account that explicitly permits a version below 1.2.
		if a.MinTLSVersion == "" || a.MinTLSVersion == "TLS1_2" {
			continue
		}
		desc := fmt.Sprintf("Storage account %q sets a minimum TLS version of %s (below TLS1_2).", a.Name, a.MinTLSVersion)
		poc := fmt.Sprintf("az storage account show --name %s --resource-group %s --query minimumTlsVersion", a.Name, a.ResourceGroup)
		out = append(out, findings.New(c.Spec(), storageResource(a), desc, poc, now))
	}
	return out, nil
}

type storageSharedKeyAccess struct{}

func (storageSharedKeyAccess) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_storage_shared_key_access", Title: "Storage account permits shared-key (account-key) authorization",
		Provider: "azure", Service: "storage", Severity: findings.SeverityMedium,
		Rationale:   "Shared-key access lets anyone holding the account key act as the account with full data-plane control, bypassing Azure AD identity, RBAC, and conditional access.",
		Impact:      "A leaked account key grants complete, unattributable access to all data in the account; rotating it disrupts every legitimate consumer.",
		Remediation: "Disable shared-key auth and require Azure AD: az storage account update --name <name> --resource-group <rg> --allow-shared-key-access false",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "3.8"}},
	}
}

func (c storageSharedKeyAccess) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.StorageAccounts {
		if !a.SharedKeyAccessAllowed {
			continue
		}
		desc := fmt.Sprintf("Storage account %q permits shared-key (account-key) authorization.", a.Name)
		poc := fmt.Sprintf("az storage account show --name %s --resource-group %s --query allowSharedKeyAccess", a.Name, a.ResourceGroup)
		out = append(out, findings.New(c.Spec(), storageResource(a), desc, poc, now))
	}
	return out, nil
}
