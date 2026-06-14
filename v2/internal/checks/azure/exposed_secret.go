package azure

import (
	"fmt"
	"sort"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(exposedSecret{}) }

// exposedSecret reports credential material the Azure secrets collector (§9.2)
// found in the control plane: App Service / Function app application settings and
// connection strings. Anyone with configuration-read access to the app — a far
// wider set than the secret's intended consumers — can read these, so each is a
// real disclosure regardless of whether the credential is still live.
//
// Hits are grouped per subscription into one aggregate finding each, carrying
// only the masked rendering (last four characters). Liveness is not asserted.
type exposedSecret struct{}

func (exposedSecret) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:        "azure_exposed_secret",
		Title:     "Secret material embedded in the Azure control plane",
		Provider:  "azure",
		Service:   "secrets",
		Severity:  findings.SeverityHigh,
		Rationale: "Credentials placed in App Service application settings or connection strings are readable by every principal with configuration-read access on the app — a much wider audience than the secret's intended consumers — and are routinely harvested after an initial foothold.",
		Impact:    "An attacker reading the app configuration lifts the credential (storage account key, database password, API token) and uses it directly for data access or lateral movement.",
		Remediation: "Move the value into Key Vault and reference it (@Microsoft.KeyVault(...)); rotate the exposed credential, since it must be treated as compromised:\n" +
			"az webapp config appsettings set ...  # replace with a Key Vault reference, then rotate the leaked secret",
		References: []string{
			"https://learn.microsoft.com/azure/app-service/app-service-key-vault-references",
			"https://learn.microsoft.com/azure/key-vault/general/overview",
		},
	}
}

func (c exposedSecret) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil || len(st.Azure.SecretHits) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()

	// Group by subscription so each finding is scoped to one account, mirroring
	// the per-account attribution the AWS exposed-secret check produces.
	bySub := map[string][]findings.Affected{}
	for _, h := range st.Azure.SecretHits {
		bySub[h.Account] = append(bySub[h.Account], findings.Affected{
			Type:   "secret",
			ID:     h.Resource,
			Region: h.Region,
			Detail: fmt.Sprintf("%s (%s) in %s %s [%s] at %q",
				h.Kind, h.Detector, surfaceLabel(h.Surface), h.Resource, h.Masked, h.Locator),
		})
	}

	subs := make([]string, 0, len(bySub))
	for sub := range bySub {
		subs = append(subs, sub)
	}
	sort.Strings(subs)

	var out []findings.Finding
	for _, sub := range subs {
		items := bySub[sub]
		sortAffected(items)
		scope := findings.Resource{
			ID: sub, Name: sub, Type: "azure_subscription", Provider: "azure", Account: sub,
		}
		desc := fmt.Sprintf("%d secret(s) are embedded in the Azure control plane (App Service settings / connection strings) in subscription %s. Values are shown masked; rotate each, as exposure means compromise.", len(items), sub)
		out = append(out, findings.NewAggregate(c.Spec(), scope, desc, items, now))
	}
	return out, nil
}

// surfaceLabel renders a state surface id for the finding detail.
func surfaceLabel(surface string) string {
	switch surface {
	case "azure_appservice_setting":
		return "App Service setting"
	case "azure_appservice_connstring":
		return "App Service connection string"
	default:
		return surface
	}
}

// sortAffected orders affected items deterministically (by region, then id).
func sortAffected(items []findings.Affected) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Region != items[j].Region {
			return items[i].Region < items[j].Region
		}
		return items[i].ID < items[j].ID
	})
}
