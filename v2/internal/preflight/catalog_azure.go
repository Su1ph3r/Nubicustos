package preflight

// nubicustosAzureActions is the authoritative set of Azure ARM operations the
// native Azure collectors, checks, and discovery invoke. Derived from the read
// calls in internal/providers/azure and internal/discovery/azure.go. Keep in
// sync when a collector adds an API call (the registration tests guard the check
// set; this list guards the access the scan needs to run).
//
// These are ARM action strings, the Azure analogue of IAM actions. Most are
// "*/read" operations granted by the Reader built-in role; the App Service
// settings/connection-string listing is a POST "action" that Reader does NOT
// grant (it needs Website Contributor or a custom role), which preflight surfaces.
var nubicustosAzureActions = []string{
	// scope / discovery
	"Microsoft.Resources/subscriptions/read",
	// storage posture
	"Microsoft.Storage/storageAccounts/read",
	// network posture (NSG rules) + reachability topology (NICs, VNets/subnets)
	"Microsoft.Network/networkSecurityGroups/read",
	"Microsoft.Network/networkInterfaces/read",
	"Microsoft.Network/virtualNetworks/read",
	// key vault posture
	"Microsoft.KeyVault/vaults/read",
	// SQL posture (server config + firewall rules)
	"Microsoft.Sql/servers/read",
	"Microsoft.Sql/servers/firewallRules/read",
	// Cosmos DB posture
	"Microsoft.DocumentDB/databaseAccounts/read",
	// Defender for Cloud plan tiers
	"Microsoft.Security/pricings/read",
	// RBAC custom role definitions
	"Microsoft.Authorization/roleDefinitions/read",
	// Monitor: activity-log alerts (CIS 5.2)
	"Microsoft.Insights/activityLogAlerts/read",
	// App Service posture + control-plane secrets (Function/Web apps)
	"Microsoft.Web/sites/Read",
	"Microsoft.Web/sites/config/Read",        // GetConfiguration: min TLS, FTPS state (Reader-granted)
	"Microsoft.Web/sites/config/list/Action", // list app settings / connection strings (needs Website Contributor)
	// Note: Microsoft.Management/managementGroups/read is required only for the
	// optional `scan --management-group` subtree scoping, so it is deliberately
	// left out of the always-required set — a subscription-scoped operator would
	// otherwise be flagged partial for an action they do not use. The Azure prober
	// still knows how to probe it if a future caller adds it to a tool's set.
}

// AzureTools is the requirement catalog for Azure scanning. Only the native
// Nubicustos engine is modeled today (no external Azure tools yet). The
// RequiredManagedPolicies field carries Azure built-in role names here (the
// remediator assigns them by name); Reader covers the read operations and
// Website Contributor covers the App Service settings-listing action.
var AzureTools = []Tool{
	{
		Key: "nubicustos", Name: "Nubicustos (native Azure checks)",
		Description:             "The built-in read-only Azure posture engine (storage, NSG, key vault, control-plane secrets)",
		RequiredManagedPolicies: []string{"Reader", "Website Contributor"},
		RequiredActions:         nubicustosAzureActions,
		RemediationPolicyName:   "NubicustosAzureReadRole",
	},
}

// AzureToolByKey returns the Azure catalog entry for key (ok=false if unknown).
func AzureToolByKey(key string) (Tool, bool) {
	for _, t := range AzureTools {
		if t.Key == key {
			return t, true
		}
	}
	return Tool{}, false
}
