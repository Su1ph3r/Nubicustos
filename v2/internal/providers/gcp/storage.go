package gcp

import (
	"errors"
	"fmt"

	storage "google.golang.org/api/storage/v1"

	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(storageCollector{}) }

type storageCollector struct{}

func (storageCollector) Name() string { return "gcp:storage" }

// Collect gathers Cloud Storage bucket posture across the in-scope projects:
// uniform bucket-level access, public access prevention, and whether the IAM
// policy grants public (allUsers/allAuthenticatedUsers) access.
func (storageCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := storage.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return err
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		listErr := svc.Buckets.List(project).Pages(sc.Ctx, func(page *storage.Buckets) error {
			for _, b := range page.Items {
				bk := state.GCSBucket{Name: b.Name, Project: project, Location: b.Location}
				if ic := b.IamConfiguration; ic != nil {
					if u := ic.UniformBucketLevelAccess; u != nil {
						bk.UniformBucketLevelAccess = u.Enabled
					}
					bk.PublicAccessPrevention = ic.PublicAccessPrevention
				}
				public, err := bucketPublic(sc, svc, b.Name)
				if err != nil {
					// Could not determine public status (e.g. getIamPolicy denied):
					// surface it rather than silently reporting the bucket as private.
					errs = append(errs, err)
				}
				bk.PublicIAM = public
				st.AddGCSBucket(bk)
			}
			return nil
		})
		if listErr != nil {
			errs = append(errs, fmt.Errorf("gcp storage: listing buckets in project %s: %w", project, listErr))
		}
	}
	return errors.Join(errs...)
}

// bucketPublic reports whether a bucket's IAM policy grants a public principal.
// It returns an error (rather than a false negative) when the policy cannot be
// read, so a denied getIamPolicy is not misreported as "not public".
func bucketPublic(sc *engine.ScanContext, svc *storage.Service, bucket string) (bool, error) {
	policy, err := svc.Buckets.GetIamPolicy(bucket).Context(sc.Ctx).Do()
	if err != nil {
		return false, fmt.Errorf("gcp storage: getIamPolicy for bucket %s: %w", bucket, err)
	}
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			if isPublicMember(m) {
				return true, nil
			}
		}
	}
	return false, nil
}
