// Package azure contains read-only Azure collectors. Each collector iterates the
// subscriptions resolved up front (plan §9.4) and populates the normalized state
// model. Collectors no-op for non-Azure scans and tolerate per-subscription
// failures so one denied subscription does not blank the rest.
package azure

import "strings"

// resourceGroupFromID extracts the resource group from an ARM resource id of the
// form /subscriptions/<sub>/resourceGroups/<rg>/providers/...; "" if absent.
func resourceGroupFromID(id string) string {
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

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func boolVal(p *bool) bool {
	return p != nil && *p
}

func int32Val(p *int32) int {
	if p == nil {
		return 0
	}
	return int(*p)
}
