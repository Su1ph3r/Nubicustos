package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(kvSoftDelete{})
	engine.RegisterCheck(kvPurgeProtection{})
	engine.RegisterCheck(kvNetworkOpen{})
}

func kvResource(v state.KeyVault) findings.Resource {
	return findings.Resource{
		ID: v.Name, Name: v.Name, Type: "azure_key_vault", Provider: "azure",
		Account: v.Subscription, Region: v.Location,
	}
}

type kvSoftDelete struct{}

func (kvSoftDelete) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_keyvault_soft_delete_disabled", Title: "Key vault does not have soft-delete enabled",
		Provider: "azure", Service: "keyvault", Severity: findings.SeverityMedium,
		Rationale:   "Without soft-delete, deleted keys/secrets are unrecoverable, enabling destructive or ransom actions with no recovery window.",
		Impact:      "An attacker (or accident) can permanently destroy cryptographic material and secrets.",
		Remediation: "az keyvault update --name <name> --resource-group <rg> --enable-soft-delete true",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "8.4"}},
	}
}

func (c kvSoftDelete) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, v := range st.Azure.KeyVaults {
		if v.SoftDeleteEnabled {
			continue
		}
		desc := fmt.Sprintf("Key vault %q does not have soft-delete enabled.", v.Name)
		poc := fmt.Sprintf("az keyvault show --name %s --query properties.enableSoftDelete", v.Name)
		out = append(out, findings.New(c.Spec(), kvResource(v), desc, poc, now))
	}
	return out, nil
}

type kvPurgeProtection struct{}

func (kvPurgeProtection) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_keyvault_purge_protection_disabled", Title: "Key vault does not have purge protection enabled",
		Provider: "azure", Service: "keyvault", Severity: findings.SeverityLow,
		Rationale:   "Purge protection blocks permanent deletion during the soft-delete retention window; without it, soft-deleted material can be purged immediately.",
		Impact:      "Cryptographic material can be permanently purged before the retention window protects it.",
		Remediation: "az keyvault update --name <name> --resource-group <rg> --enable-purge-protection true",
	}
}

func (c kvPurgeProtection) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, v := range st.Azure.KeyVaults {
		if v.PurgeProtection {
			continue
		}
		desc := fmt.Sprintf("Key vault %q does not have purge protection enabled.", v.Name)
		poc := fmt.Sprintf("az keyvault show --name %s --query properties.enablePurgeProtection", v.Name)
		out = append(out, findings.New(c.Spec(), kvResource(v), desc, poc, now))
	}
	return out, nil
}

type kvNetworkOpen struct{}

func (kvNetworkOpen) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_keyvault_network_default_allow", Title: "Key vault network rules default to Allow",
		Provider: "azure", Service: "keyvault", Severity: findings.SeverityMedium,
		Rationale:   "A key vault whose network ACL default action is Allow is reachable from any network, not just trusted ones.",
		Impact:      "The vault's data plane is exposed to networks beyond those explicitly intended.",
		Remediation: "Set the default action to Deny: az keyvault network-rule add / az keyvault update --default-action Deny",
	}
}

func (c kvNetworkOpen) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, v := range st.Azure.KeyVaults {
		if !v.NetworkDefaultAllow {
			continue
		}
		desc := fmt.Sprintf("Key vault %q network rules default to Allow (open to all networks).", v.Name)
		poc := fmt.Sprintf("az keyvault show --name %s --query properties.networkAcls.defaultAction", v.Name)
		out = append(out, findings.New(c.Spec(), kvResource(v), desc, poc, now))
	}
	return out, nil
}
