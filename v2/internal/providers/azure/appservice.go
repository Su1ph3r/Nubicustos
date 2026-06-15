package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(appServiceCollector{}) }

// appServiceCollector gathers App Service / Function web-app posture across the
// in-scope subscriptions: HTTPS enforcement (from the site object) plus the
// minimum TLS version and FTPS state (from the site configuration). It is the
// posture counterpart to the secrets-scan collector, which reads the same web
// apps for embedded credentials. Per-subscription and per-app failures are
// tolerated so one inaccessible app never blanks the rest.
type appServiceCollector struct{}

func (appServiceCollector) Name() string { return "azure:appservice" }

func (appServiceCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		client, err := armappservice.NewWebAppsClient(sub, sc.Azure.Credential, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("azure appservice: building client for subscription %s: %w", sub, err))
			continue
		}
		pager := client.NewListPager(nil)
		for pager.More() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("azure appservice: listing web apps in subscription %s: %w", sub, err))
				break
			}
			for _, site := range page.Value {
				if site == nil {
					continue
				}
				name := str(site.Name)
				rg := resourceGroupFromID(str(site.ID))
				if name == "" || rg == "" {
					continue
				}
				app := state.WebApp{
					Name:          name,
					ResourceGroup: rg,
					Subscription:  sub,
					Location:      str(site.Location),
				}
				if site.Properties != nil {
					app.HTTPSOnly = boolVal(site.Properties.HTTPSOnly)
				}
				// The minimum TLS version and FTPS state live in the site config, a
				// separate read. A failure there leaves those fields zero (the checks
				// skip empty values) without dropping the app's HTTPS posture.
				if cfg, err := client.GetConfiguration(sc.Ctx, rg, name, nil); err == nil && cfg.Properties != nil {
					if cfg.Properties.MinTLSVersion != nil {
						app.MinTLSVersion = string(*cfg.Properties.MinTLSVersion)
					}
					if cfg.Properties.FtpsState != nil {
						app.FtpsState = string(*cfg.Properties.FtpsState)
					}
				}
				st.AddWebApp(app)
			}
		}
	}
	return errors.Join(errs...)
}
