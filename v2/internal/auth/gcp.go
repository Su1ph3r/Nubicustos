package auth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// gcpScope is the read-only cloud-platform scope; everything the scanner does is
// a Describe/List/Get, so it never needs write access.
const gcpScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

// ResolveGCP resolves Application Default Credentials and validates them with a
// single Resource Manager call, so any credential problem surfaces up front
// (before the scan fans out) rather than mid-collection. ADC covers
// `gcloud auth application-default login`, GOOGLE_APPLICATION_CREDENTIALS, and
// attached service accounts (GCE/GKE/Cloud Run) with no extra configuration.
func ResolveGCP(ctx context.Context) (*google.Credentials, error) {
	creds, err := google.FindDefaultCredentials(ctx, gcpScope)
	if err != nil {
		return nil, fmt.Errorf("resolving GCP application default credentials: %w "+
			"(run `gcloud auth application-default login` or set GOOGLE_APPLICATION_CREDENTIALS)", err)
	}
	svc, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("building resource manager client: %w", err)
	}
	if _, err := svc.Projects.List().PageSize(1).Context(ctx).Do(); err != nil {
		return nil, fmt.Errorf("validating GCP credentials: %w", err)
	}
	return creds, nil
}
