package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(secretsScanCollector{}) }

// secretsScanCollector scans the Azure control plane for embedded credentials
// (plan §9.2), extending the cloud-side secrets capability to Azure. App Service
// (and Function app) application settings and connection strings are the richest
// Azure surface — the equivalent of Lambda env vars — where database passwords,
// storage account keys, and API tokens routinely sit in plaintext readable by
// anyone with config access.
//
//   - Application settings (key/value) run through the shared detector.
//   - Connection strings are credentials by construction (they carry AccountKey /
//     Password), so each is flagged directly, masked.
//
// Only the masked detection — never the raw value — is recorded in state. Per-
// subscription and per-app failures are tolerated so one inaccessible app or
// subscription never blanks the rest.
type secretsScanCollector struct{}

func (secretsScanCollector) Name() string { return "azure:secrets-scan" }

func (secretsScanCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armappservice.NewWebAppsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure secrets: building web apps client for subscription %s: %w", sub, err))
			continue
		}
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure secrets: listing web apps in subscription %s: %w", sub, err))
				break
			}
			for _, site := range page.Value {
				if site == nil {
					continue
				}
				name := str(site.Name)
				rg := resourceGroupFromID(str(site.ID))
				loc := str(site.Location)
				if name == "" || rg == "" {
					continue
				}
				scanAppSettings(sc, client, st, sub, rg, name, loc)
				scanConnectionStrings(sc, client, st, sub, rg, name, loc)
			}
		}
	}
	return errors.Join(errs...)
}

// scanAppSettings runs the shared detector over a web app's application settings.
func scanAppSettings(sc *engine.ScanContext, client *armappservice.WebAppsClient, st *state.State, sub, rg, name, loc string) {
	resp, err := client.ListApplicationSettings(sc.Ctx, rg, name, nil)
	if err != nil {
		return
	}
	for k, v := range resp.Properties {
		if v == nil {
			continue
		}
		for _, m := range secrets.ScanKeyValue(k, *v, k) {
			st.AddAzureSecretHit(azureSecretHit(m, "azure_appservice_setting", name, sub, loc, k))
		}
	}
}

// scanConnectionStrings flags every configured connection string: these always
// carry credentials, so each is a hit on its own — no detector heuristic needed.
func scanConnectionStrings(sc *engine.ScanContext, client *armappservice.WebAppsClient, st *state.State, sub, rg, name, loc string) {
	resp, err := client.ListConnectionStrings(sc.Ctx, rg, name, nil)
	if err != nil {
		return
	}
	for k, pair := range resp.Properties {
		if pair == nil || pair.Value == nil || *pair.Value == "" {
			continue
		}
		val := *pair.Value
		st.AddAzureSecretHit(state.SecretHit{
			Detector: "azure_connection_string",
			Kind:     "App Service connection string (carries inline credentials)",
			Surface:  "azure_appservice_connstring",
			Resource: name,
			Account:  sub,
			Region:   loc,
			Locator:  k,
			Masked:   secrets.Mask(val),
			LastFour: lastFour(val),
		})
	}
}

// azureSecretHit folds a detector Match plus its Azure source into a state record.
func azureSecretHit(m secrets.Match, surface, resource, sub, loc, locator string) state.SecretHit {
	return state.SecretHit{
		Detector: m.Detector,
		Kind:     m.Kind,
		Surface:  surface,
		Resource: resource,
		Account:  sub,
		Region:   loc,
		Locator:  locator,
		Masked:   m.Masked,
		LastFour: m.LastFour,
		Entropy:  m.Entropy,
	}
}

// lastFour returns the last four characters of a value, for correlation without
// exposure; empty when the value is too short to mask meaningfully.
func lastFour(s string) string {
	if len(s) <= 4 {
		return ""
	}
	return s[len(s)-4:]
}
