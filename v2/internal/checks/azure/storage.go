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
