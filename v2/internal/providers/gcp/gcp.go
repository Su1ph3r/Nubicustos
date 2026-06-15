// Package gcp contains read-only GCP collectors. Each collector iterates the
// projects resolved up front (plan §9.4) and populates the normalized state
// model. Collectors no-op for non-GCP scans and tolerate per-project failures so
// one denied project does not blank the rest.
package gcp

import (
	"context"
	"strings"

	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// isPublicMember reports whether an IAM member string grants access to anyone on
// the internet (the all-users / all-authenticated principals).
func isPublicMember(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

// shortResourceName returns the final path segment of a GCP resource name, e.g.
// "projects/p/locations/l/functions/fn" -> "fn". Empty input returns "".
func shortResourceName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		return full[i+1:]
	}
	return full
}

// regionFromFunction pulls the location out of a Cloud Functions resource name
// of the form "projects/<p>/locations/<loc>/functions/<fn>"; "" if absent.
func regionFromFunction(name string) string {
	const marker = "/locations/"
	i := strings.Index(name, marker)
	if i < 0 {
		return ""
	}
	rest := name[i+len(marker):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// zoneShort reduces a compute zone URL (or bare zone) to its short name, e.g.
// ".../zones/us-central1-a" -> "us-central1-a".
func zoneShort(zone string) string { return shortResourceName(zone) }

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
