package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(entraFederatedCredential{})
	engine.RegisterCheck(entraMultiTenantApp{})
	engine.RegisterCheck(entraExpiredCredential{})
}

func appResource(a state.AzureAppRegistration) findings.Resource {
	return findings.Resource{
		ID: a.AppID, Name: a.DisplayName, Type: "azure_app_registration", Provider: "azure",
	}
}

type entraFederatedCredential struct{}

func (entraFederatedCredential) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_entra_federated_credential", Title: "App registration trusts an external workload-identity issuer",
		Provider: "azure", Service: "entra", Severity: findings.SeverityMedium,
		Rationale:   "A federated identity credential lets an external OIDC issuer (e.g. GitHub Actions, another cloud) obtain tokens as this app with no stored secret. If the subject claim is not tightly scoped (specific repo/branch/environment), any workload the issuer trusts can impersonate the app — the cloud-to-cloud equivalent of a loose OIDC role trust.",
		Impact:      "An over-broad subject lets unintended external workloads authenticate as the app and exercise its Entra and Azure permissions.",
		Remediation: "Verify each federated credential's subject is scoped to the exact external identity (e.g. repo:org/repo:environment:prod), and remove unused credentials: az ad app federated-credential list --id <appId>",
		References:  []string{"https://learn.microsoft.com/entra/workload-id/workload-identity-federation"},
	}
}

func (c entraFederatedCredential) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.AppRegistrations {
		for _, fc := range a.FederatedCreds {
			desc := fmt.Sprintf("App registration %q (appId %s) trusts federated issuer %q with subject %q — verify the subject is scoped to a specific external identity.",
				a.DisplayName, a.AppID, fc.Issuer, fc.Subject)
			poc := fmt.Sprintf("az ad app federated-credential list --id %s", a.AppID)
			out = append(out, findings.New(c.Spec(), appResource(a), desc, poc, now))
		}
	}
	return out, nil
}

type entraMultiTenantApp struct{}

func (entraMultiTenantApp) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_entra_multi_tenant_app", Title: "App registration is multi-tenant",
		Provider: "azure", Service: "entra", Severity: findings.SeverityMedium,
		Rationale:   "A multi-tenant app accepts sign-ins and consent from accounts outside the home tenant, widening the trust surface; if over-privileged it can be consented into other tenants or abused for cross-tenant access.",
		Impact:      "External tenants can consent to and use the app; combined with broad permissions this is a cross-tenant access path.",
		Remediation: "If single-tenant use is intended, set the audience accordingly: az ad app update --id <appId> --sign-in-audience AzureADMyOrg",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "1.x"}},
	}
}

func (c entraMultiTenantApp) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.AppRegistrations {
		if !a.MultiTenant {
			continue
		}
		desc := fmt.Sprintf("App registration %q (appId %s) is multi-tenant (admits accounts outside the home tenant).", a.DisplayName, a.AppID)
		poc := fmt.Sprintf("az ad app show --id %s --query signInAudience", a.AppID)
		out = append(out, findings.New(c.Spec(), appResource(a), desc, poc, now))
	}
	return out, nil
}

type entraExpiredCredential struct{}

func (entraExpiredCredential) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_entra_expired_app_credential", Title: "App registration has an expired credential still configured",
		Provider: "azure", Service: "entra", Severity: findings.SeverityLow,
		Rationale:   "An expired client secret or certificate left on an app registration is dead weight that obscures credential inventory and signals weak rotation hygiene; stale credentials are a common source of confusion and missed rotation.",
		Impact:      "Expired credentials clutter the trust inventory and indicate credentials are not being managed/rotated cleanly.",
		Remediation: "Remove expired credentials: az ad app credential delete --id <appId> --key-id <id>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "1.x"}},
	}
}

func (c entraExpiredCredential) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, a := range st.Azure.AppRegistrations {
		if !a.HasExpiredCredential {
			continue
		}
		desc := fmt.Sprintf("App registration %q (appId %s) has an expired credential still configured.", a.DisplayName, a.AppID)
		poc := fmt.Sprintf("az ad app credential list --id %s", a.AppID)
		out = append(out, findings.New(c.Spec(), appResource(a), desc, poc, now))
	}
	return out, nil
}
