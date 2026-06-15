package azure

import (
	"time"

	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(entraCollector{}) }

// graphScopes is the default-scope token request for Microsoft Graph; the
// credential must carry directory read consent (Application.Read.All /
// Directory.Read.All) for the calls to succeed.
var graphScopes = []string{"https://graph.microsoft.com/.default"}

// entraCollector gathers Entra ID (Azure AD) app-registration posture — the
// directory-identity trust surface ARM cannot see (plan §9.3): multi-tenant
// apps, expired-but-present credentials, and workload-identity federated
// credentials (the OIDC-trust surface).
//
// Entra is tenant-scoped, so this runs once per scan regardless of how many
// subscriptions are in scope. Graph access is a separate consent surface from
// ARM RBAC, so when the scan credential lacks directory read the collector skips
// cleanly (returns nil) rather than failing the scan.
type entraCollector struct{}

func (entraCollector) Name() string { return "azure:entra" }

func (entraCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	client, err := msgraph.NewGraphServiceClientWithCredentials(sc.Azure.Credential, graphScopes)
	if err != nil {
		return nil // cannot build a Graph client → skip Entra, do not fail the scan
	}
	now := time.Now().UTC()

	builder := client.Applications()
	for {
		resp, err := builder.Get(sc.Ctx, nil)
		if err != nil {
			// No directory access (or Graph unreachable): skip Entra cleanly. This
			// is expected for subscription-Reader scan credentials.
			return nil
		}
		for _, app := range resp.GetValue() {
			st.AddAzureAppRegistration(normalizeApp(sc, client, app, now))
		}
		next := resp.GetOdataNextLink()
		if next == nil || *next == "" {
			break
		}
		builder = client.Applications().WithUrl(*next)
	}
	return nil
}

func normalizeApp(sc *engine.ScanContext, client *msgraph.GraphServiceClient, app graphmodels.Applicationable, now time.Time) state.AzureAppRegistration {
	out := state.AzureAppRegistration{
		DisplayName: str(app.GetDisplayName()),
		AppID:       str(app.GetAppId()),
		MultiTenant: multiTenantAudience(str(app.GetSignInAudience())),
	}
	out.HasExpiredCredential = anyExpired(app, now)
	out.FederatedCreds = federatedCreds(sc, client, app)
	return out
}

// multiTenantAudience reports whether a signInAudience admits accounts beyond the
// app's home tenant.
func multiTenantAudience(audience string) bool {
	return audience == "AzureADMultipleOrgs" || audience == "AzureADandPersonalMicrosoftAccount"
}

// anyExpired reports whether any password or key credential's end date is in the
// past (a stale credential left configured).
func anyExpired(app graphmodels.Applicationable, now time.Time) bool {
	for _, pc := range app.GetPasswordCredentials() {
		if end := pc.GetEndDateTime(); end != nil && end.Before(now) {
			return true
		}
	}
	for _, kc := range app.GetKeyCredentials() {
		if end := kc.GetEndDateTime(); end != nil && end.Before(now) {
			return true
		}
	}
	return false
}

// federatedCreds fetches an app's workload-identity federated credentials. A
// per-app failure yields no creds for that app rather than aborting the sweep.
func federatedCreds(sc *engine.ScanContext, client *msgraph.GraphServiceClient, app graphmodels.Applicationable) []state.AzureFederatedCred {
	id := app.GetId()
	if id == nil || *id == "" {
		return nil
	}
	resp, err := client.Applications().ByApplicationId(*id).FederatedIdentityCredentials().Get(sc.Ctx, nil)
	if err != nil {
		return nil
	}
	var out []state.AzureFederatedCred
	for _, fc := range resp.GetValue() {
		out = append(out, state.AzureFederatedCred{
			Name:    str(fc.GetName()),
			Issuer:  str(fc.GetIssuer()),
			Subject: str(fc.GetSubject()),
		})
	}
	return out
}
