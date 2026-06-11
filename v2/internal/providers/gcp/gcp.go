// Package gcp contains read-only GCP collectors. Each collector iterates the
// projects resolved up front (plan §9.4) and populates the normalized state
// model. Collectors no-op for non-GCP scans and tolerate per-project failures so
// one denied project does not blank the rest.
package gcp

import (
	"context"

	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// isPublicMember reports whether an IAM member string grants access to anyone on
// the internet (the all-users / all-authenticated principals).
func isPublicMember(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

// EnabledProjects enumerates the ACTIVE projects the credential can see (plan
// §9.4 — GCP discovery), so the scan fans out across the estate.
func EnabledProjects(ctx context.Context, creds *google.Credentials) ([]string, error) {
	svc, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	var out []string
	err = svc.Projects.List().Context(ctx).Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, p := range page.Projects {
			if p.LifecycleState == "ACTIVE" {
				out = append(out, p.ProjectId)
			}
		}
		return nil
	})
	return out, err
}
