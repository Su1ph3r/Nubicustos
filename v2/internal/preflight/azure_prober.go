package preflight

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// errNoResource signals that an action could not be probed because no resource
// of the required type exists to read (e.g. listing a web app's config when the
// subscription has no web apps). The probe reports this as unknown, not denied.
var errNoResource = errors.New("no resource of this type to probe")

// NewAzureProber returns a Prober that confirms each required ARM action by
// performing one representative read against the subscription. A live read is
// authoritative for Azure access — it reflects deny assignments and Azure Policy
// that role math would miss — so Azure preflight runs probe-only. subscription is
// the in-scope subscription resource-level reads target.
func NewAzureProber(cred azcore.TokenCredential, subscription string) Prober {
	return &azureProber{reads: liveAzureReads(cred, subscription)}
}

// azureProber maps each ARM action to a representative read. The reads map is the
// test seam: the live constructor wires SDK calls; tests inject fakes.
type azureProber struct {
	reads map[string]func(ctx context.Context) error
}

func (p *azureProber) Probe(ctx context.Context, action string) Decision {
	read, ok := p.reads[action]
	if !ok {
		return DecisionUnknown // not probed
	}
	return azureDecision(read(ctx))
}

// azureDecision classifies a read outcome: success → allowed; an authorization
// failure (403 / AuthorizationFailed) → denied; no resource to probe or any other
// error → unknown (never penalize on a non-authorization failure).
func azureDecision(err error) Decision {
	switch {
	case err == nil:
		return DecisionAllowed
	case errors.Is(err, errNoResource):
		return DecisionUnknown
	case isAzureAuthFailure(err):
		return DecisionDenied
	default:
		return DecisionUnknown
	}
}

// isAzureAuthFailure reports whether err is Azure RBAC denying the read — an
// HTTP 403 or the AuthorizationFailed error code.
func isAzureAuthFailure(err error) bool {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		if re.StatusCode == http.StatusForbidden {
			return true
		}
		switch re.ErrorCode {
		case "AuthorizationFailed", "Forbidden", "InsufficientPrivileges":
			return true
		}
	}
	return false
}

// liveAzureReads wires each ARM action to a representative first-page read. Only
// the first page is fetched — enough to confirm the read is permitted. Resource-
// level reads target subscription; subscription/management-group reads are global.
func liveAzureReads(cred azcore.TokenCredential, subscription string) map[string]func(ctx context.Context) error {
	return map[string]func(ctx context.Context) error{
		"Microsoft.Resources/subscriptions/read": func(ctx context.Context) error {
			c, err := armsubscriptions.NewClient(cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager(nil))
		},
		"Microsoft.Management/managementGroups/read": func(ctx context.Context) error {
			c, err := armmanagementgroups.NewClient(cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager(nil))
		},
		"Microsoft.Storage/storageAccounts/read": func(ctx context.Context) error {
			c, err := armstorage.NewAccountsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager(nil))
		},
		"Microsoft.Network/networkSecurityGroups/read": func(ctx context.Context) error {
			c, err := armnetwork.NewSecurityGroupsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListAllPager(nil))
		},
		"Microsoft.KeyVault/vaults/read": func(ctx context.Context) error {
			c, err := armkeyvault.NewVaultsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListBySubscriptionPager(nil))
		},
		"Microsoft.Sql/servers/read": func(ctx context.Context) error {
			c, err := armsql.NewServersClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager(nil))
		},
		"Microsoft.DocumentDB/databaseAccounts/read": func(ctx context.Context) error {
			c, err := armcosmos.NewDatabaseAccountsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager(nil))
		},
		"Microsoft.Security/pricings/read": func(ctx context.Context) error {
			c, err := armsecurity.NewPricingsClient(cred, nil)
			if err != nil {
				return err
			}
			_, err = c.List(ctx, "subscriptions/"+subscription, nil)
			return err
		},
		"Microsoft.Authorization/roleDefinitions/read": func(ctx context.Context) error {
			c, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager("/subscriptions/"+subscription, nil))
		},
		"Microsoft.Sql/servers/firewallRules/read": func(ctx context.Context) error {
			// Listing firewall rules needs an actual server; find one first.
			sc, err := armsql.NewServersClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			pager := sc.NewListPager(nil)
			if !pager.More() {
				return errNoResource
			}
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			if len(page.Value) == 0 || page.Value[0] == nil || page.Value[0].Name == nil {
				return errNoResource
			}
			srv := page.Value[0]
			fw, err := armsql.NewFirewallRulesClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, fw.NewListByServerPager(rgFromID(deref(srv.ID)), deref(srv.Name), nil))
		},
		"Microsoft.Web/sites/Read": func(ctx context.Context) error {
			c, err := armappservice.NewWebAppsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			return drainFirst(ctx, c.NewListPager(nil))
		},
		"Microsoft.Web/sites/config/Read": func(ctx context.Context) error {
			// Reading a web app's configuration needs an actual app; find one first.
			c, err := armappservice.NewWebAppsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			pager := c.NewListPager(nil)
			if !pager.More() {
				return errNoResource
			}
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			if len(page.Value) == 0 || page.Value[0] == nil || page.Value[0].Name == nil {
				return errNoResource
			}
			site := page.Value[0]
			_, err = c.GetConfiguration(ctx, rgFromID(deref(site.ID)), deref(site.Name), nil)
			return err
		},
		"Microsoft.Web/sites/config/list/Action": func(ctx context.Context) error {
			// Listing a web app's settings needs an actual app; find one first.
			c, err := armappservice.NewWebAppsClient(subscription, cred, nil)
			if err != nil {
				return err
			}
			pager := c.NewListPager(nil)
			if !pager.More() {
				return errNoResource
			}
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			if len(page.Value) == 0 || page.Value[0] == nil || page.Value[0].Name == nil {
				return errNoResource
			}
			site := page.Value[0]
			rg := rgFromID(deref(site.ID))
			_, err = c.ListApplicationSettings(ctx, rg, deref(site.Name), nil)
			return err
		},
	}
}

// drainFirst fetches the first page of a pager to confirm the read is permitted.
// The generic parameter is the page type, which we ignore.
func drainFirst[T any](ctx context.Context, pager *runtime.Pager[T]) error {
	if !pager.More() {
		return nil
	}
	_, err := pager.NextPage(ctx)
	return err
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// rgFromID pulls the resource group out of an ARM resource id of the form
// /subscriptions/<sub>/resourceGroups/<rg>/providers/...; "" if absent.
func rgFromID(id string) string {
	const marker = "/resourceGroups/"
	i := strings.Index(strings.ToLower(id), strings.ToLower(marker))
	if i < 0 {
		return ""
	}
	rest := id[i+len(marker):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}
