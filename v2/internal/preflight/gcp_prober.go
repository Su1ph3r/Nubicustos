package preflight

import (
	"context"

	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// NewGCPProber returns a Prober backed by Resource Manager's TestIamPermissions —
// GCP's authoritative "which of these permissions do I hold" API. The whole
// required set is checked in one batch call at construction (against the project),
// then served per action. This is no destructive attempt: it is the canonical
// can-i check, so GCP preflight needs no separate read probe.
func NewGCPProber(ctx context.Context, creds *google.Credentials, projectID string) Prober {
	p := &gcpProber{queried: map[string]bool{}, granted: map[string]bool{}}
	for _, perm := range nubicustosGCPPermissions {
		p.queried[perm] = true
	}

	svc, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return p // ok stays false → every action reports unknown
	}
	resp, err := svc.Projects.TestIamPermissions(projectID,
		&cloudresourcemanager.TestIamPermissionsRequest{Permissions: nubicustosGCPPermissions}).Context(ctx).Do()
	if err != nil {
		return p
	}
	for _, g := range resp.Permissions {
		p.granted[g] = true
	}
	p.ok = true
	return p
}

// gcpProber serves decisions from a single batched TestIamPermissions result.
// queried records which permissions were tested (so an unrelated action is
// reported unknown, not denied); granted records which came back held; ok is
// false when the permission check itself could not run.
type gcpProber struct {
	queried map[string]bool
	granted map[string]bool
	ok      bool
}

func (p *gcpProber) Probe(_ context.Context, action string) Decision {
	switch {
	case !p.ok || !p.queried[action]:
		return DecisionUnknown
	case p.granted[action]:
		return DecisionAllowed
	default:
		return DecisionDenied
	}
}
