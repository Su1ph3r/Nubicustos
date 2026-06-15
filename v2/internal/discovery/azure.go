// Azure org-wide discovery (plan §9.4). Unlike AWS, one credential already spans
// every subscription the identity can see — there is no per-account role to
// assume — so discovery here is about *scoping and classification*: enumerate the
// visible subscriptions, optionally restrict to a management-group subtree, drop
// excluded / disabled ones (with a recorded reason so a partial run never reads
// as full coverage), and hand back the in-scope set for the scan to fan out over.
package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// AzureOptions controls subscription scoping.
type AzureOptions struct {
	Subscriptions   []string // explicit allowlist — only these subscription ids are considered
	Exclude         []string // subscription ids to skip
	ManagementGroup string   // restrict to subscriptions under this management group (recursive)
}

// AzureSubscription is an in-scope subscription ready to scan.
type AzureSubscription struct {
	ID    string
	Name  string
	State string
}

// AzureResult is the outcome of subscription discovery.
type AzureResult struct {
	Subscriptions []AzureSubscription // in-scope, sorted by id
	Skipped       []Skipped           // excluded / disabled / out-of-scope, with reasons
}

// azureSub is the provider-agnostic shape the pure core works over.
type azureSub struct {
	ID, Name, State string
}

// azureSubLister enumerates subscriptions; the real impl wraps the ARM client, a
// fake drives the tests.
type azureSubLister interface {
	listSubscriptions(ctx context.Context) ([]azureSub, error)
}

// azureMGLister resolves the set of subscription ids beneath a management group.
type azureMGLister interface {
	subsUnderManagementGroup(ctx context.Context, mg string) (map[string]bool, error)
}

// AzureSubscriptions enumerates the subscriptions visible to cred and returns the
// in-scope set after applying management-group, allowlist, and exclude scoping.
func AzureSubscriptions(ctx context.Context, cred azcore.TokenCredential, o AzureOptions) (*AzureResult, error) {
	subClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, err
	}
	lister := &armSubLister{cli: subClient}

	var mgLister azureMGLister
	if o.ManagementGroup != "" {
		mgClient, err := armmanagementgroups.NewClient(cred, nil)
		if err != nil {
			return nil, err
		}
		mgLister = &armMGLister{cli: mgClient}
	}
	return discoverAzure(ctx, lister, mgLister, o)
}

// discoverAzure is the SDK-independent core: enumerate, scope to the management
// group, then apply allowlist/exclude/state rules. Testable with fakes.
func discoverAzure(ctx context.Context, lister azureSubLister, mgLister azureMGLister, o AzureOptions) (*AzureResult, error) {
	subs, err := lister.listSubscriptions(ctx)
	if err != nil {
		return nil, err
	}

	var inMG map[string]bool
	if o.ManagementGroup != "" {
		if mgLister == nil {
			return nil, fmt.Errorf("management-group scoping requested but no management-group lister available")
		}
		inMG, err = mgLister.subsUnderManagementGroup(ctx, o.ManagementGroup)
		if err != nil {
			return nil, fmt.Errorf("resolving subscriptions under management group %q: %w", o.ManagementGroup, err)
		}
	}

	allow := toSet(o.Subscriptions)
	exclude := toSet(o.Exclude)

	res := &AzureResult{}
	for _, s := range subs {
		switch {
		case len(allow) > 0 && !allow[s.ID]:
			continue // not on the explicit allowlist — silently out of scope
		case exclude[s.ID]:
			res.Skipped = append(res.Skipped, Skipped{s.ID, s.Name, "excluded"})
			continue
		case inMG != nil && !inMG[s.ID]:
			res.Skipped = append(res.Skipped, Skipped{s.ID, s.Name, "outside management group " + o.ManagementGroup})
			continue
		case !strings.EqualFold(s.State, string(armsubscriptions.SubscriptionStateEnabled)):
			res.Skipped = append(res.Skipped, Skipped{s.ID, s.Name, "state " + s.State})
			continue
		}
		res.Subscriptions = append(res.Subscriptions, AzureSubscription{ID: s.ID, Name: s.Name, State: s.State})
	}

	sort.Slice(res.Subscriptions, func(i, j int) bool { return res.Subscriptions[i].ID < res.Subscriptions[j].ID })
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].ID < res.Skipped[j].ID })
	return res, nil
}

// IDs returns just the in-scope subscription ids, for the scan session.
func (r *AzureResult) IDs() []string {
	out := make([]string, len(r.Subscriptions))
	for i, s := range r.Subscriptions {
		out[i] = s.ID
	}
	return out
}

// armSubLister is the live subscriptions-backed lister.
type armSubLister struct{ cli *armsubscriptions.Client }

func (l *armSubLister) listSubscriptions(ctx context.Context) ([]azureSub, error) {
	var out []azureSub
	pager := l.cli.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, fmt.Errorf("listing Azure subscriptions: %w", err)
		}
		for _, s := range page.Value {
			if s == nil || s.SubscriptionID == nil {
				continue
			}
			sub := azureSub{ID: *s.SubscriptionID}
			if s.DisplayName != nil {
				sub.Name = *s.DisplayName
			}
			if s.State != nil {
				sub.State = string(*s.State)
			}
			out = append(out, sub)
		}
	}
	return out, nil
}

// armMGLister resolves subscriptions under a management group subtree via the
// descendants API, which already flattens the whole hierarchy.
type armMGLister struct{ cli *armmanagementgroups.Client }

func (l *armMGLister) subsUnderManagementGroup(ctx context.Context, mg string) (map[string]bool, error) {
	out := map[string]bool{}
	pager := l.cli.NewGetDescendantsPager(mg, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range page.Value {
			if d == nil || d.Type == nil || d.Name == nil {
				continue
			}
			// Descendant subscriptions carry the subscriptions type; the Name field
			// holds the bare subscription id.
			if strings.EqualFold(*d.Type, "Microsoft.Management/managementGroups/subscriptions") ||
				strings.EqualFold(*d.Type, "/subscriptions") {
				out[*d.Name] = true
			}
		}
	}
	return out, nil
}
