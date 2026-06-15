// GCP estate discovery (plan §9.4). Like Azure, one credential already spans
// every project the identity can see, so discovery here is scoping and
// classification: enumerate the visible projects, drop excluded and non-active
// ones (with a recorded reason so a partial run never reads as full coverage),
// and hand back the in-scope set for the scan to fan out over.
package discovery

import (
	"context"
	"sort"

	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// GCPOptions controls project scoping.
type GCPOptions struct {
	Projects []string // explicit allowlist — only these project ids are considered
	Exclude  []string // project ids to skip
}

// GCPProject is an in-scope project ready to scan.
type GCPProject struct {
	ID   string
	Name string
}

// GCPResult is the outcome of project discovery.
type GCPResult struct {
	Projects []GCPProject // in-scope, sorted by id
	Skipped  []Skipped    // excluded / non-active, with reasons
}

// gcpProj is the provider-agnostic shape the pure core works over.
type gcpProj struct {
	ID, Name, State string
}

// gcpProjectLister enumerates projects; the real impl wraps Resource Manager, a
// fake drives the tests.
type gcpProjectLister interface {
	listProjects(ctx context.Context) ([]gcpProj, error)
}

// GCPProjects enumerates the projects visible to creds and returns the in-scope
// set after applying the allowlist and excludes.
func GCPProjects(ctx context.Context, creds *google.Credentials, o GCPOptions) (*GCPResult, error) {
	svc, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	return discoverGCP(ctx, &crmLister{svc: svc}, o)
}

// discoverGCP is the SDK-independent core: enumerate, then apply allowlist /
// exclude / lifecycle rules. Testable with a fake lister.
func discoverGCP(ctx context.Context, lister gcpProjectLister, o GCPOptions) (*GCPResult, error) {
	projs, err := lister.listProjects(ctx)
	if err != nil {
		return nil, err
	}
	allow := toSet(o.Projects)
	exclude := toSet(o.Exclude)

	res := &GCPResult{}
	for _, p := range projs {
		switch {
		case len(allow) > 0 && !allow[p.ID]:
			continue // not on the explicit allowlist — silently out of scope
		case exclude[p.ID]:
			res.Skipped = append(res.Skipped, Skipped{p.ID, p.Name, "excluded"})
			continue
		case p.State != "ACTIVE":
			res.Skipped = append(res.Skipped, Skipped{p.ID, p.Name, "state " + p.State})
			continue
		}
		res.Projects = append(res.Projects, GCPProject{ID: p.ID, Name: p.Name})
	}
	sort.Slice(res.Projects, func(i, j int) bool { return res.Projects[i].ID < res.Projects[j].ID })
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].ID < res.Skipped[j].ID })
	return res, nil
}

// IDs returns just the in-scope project ids, for the scan session.
func (r *GCPResult) IDs() []string {
	out := make([]string, len(r.Projects))
	for i, p := range r.Projects {
		out[i] = p.ID
	}
	return out
}

// crmLister is the live Resource-Manager-backed lister.
type crmLister struct{ svc *cloudresourcemanager.Service }

func (l *crmLister) listProjects(ctx context.Context) ([]gcpProj, error) {
	var out []gcpProj
	err := l.svc.Projects.List().Context(ctx).Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, p := range page.Projects {
			out = append(out, gcpProj{ID: p.ProjectId, Name: p.Name, State: p.LifecycleState})
		}
		return nil
	})
	return out, err
}
