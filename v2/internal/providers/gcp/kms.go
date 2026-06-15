package gcp

import (
	"errors"
	"fmt"

	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(kmsCollector{}) }

type kmsCollector struct{}

func (kmsCollector) Name() string { return "gcp:kms" }

// Collect gathers Cloud KMS key posture across the in-scope projects: rotation
// configuration and whether a key's IAM policy grants public access. Keys live
// under locations → key rings → crypto keys, so the collector walks that tree.
func (kmsCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := cloudkms.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp kms: building client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		if err := collectProjectKMS(sc, svc, st, project); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func collectProjectKMS(sc *engine.ScanContext, svc *cloudkms.Service, st *state.State, project string) error {
	var errs []error
	locParent := "projects/" + project
	listErr := svc.Projects.Locations.List(locParent).Pages(sc.Ctx, func(lp *cloudkms.ListLocationsResponse) error {
		for _, loc := range lp.Locations {
			krParent := loc.Name // projects/<p>/locations/<loc>
			krErr := svc.Projects.Locations.KeyRings.List(krParent).Pages(sc.Ctx, func(kr *cloudkms.ListKeyRingsResponse) error {
				for _, ring := range kr.KeyRings {
					collectKeyRing(sc, svc, st, project, loc.LocationId, ring.Name)
				}
				return nil
			})
			if krErr != nil {
				errs = append(errs, fmt.Errorf("gcp kms: listing key rings in %s/%s: %w", project, loc.LocationId, krErr))
			}
		}
		return nil
	})
	if listErr != nil {
		errs = append(errs, fmt.Errorf("gcp kms: listing locations in project %s: %w", project, listErr))
	}
	return errors.Join(errs...)
}

func collectKeyRing(sc *engine.ScanContext, svc *cloudkms.Service, st *state.State, project, location, ringName string) {
	_ = svc.Projects.Locations.KeyRings.CryptoKeys.List(ringName).Pages(sc.Ctx, func(ck *cloudkms.ListCryptoKeysResponse) error {
		for _, key := range ck.CryptoKeys {
			k := state.KMSCryptoKey{
				Name:            shortResourceName(key.Name),
				Project:         project,
				Location:        location,
				KeyRing:         shortResourceName(ringName),
				Purpose:         key.Purpose,
				RotationEnabled: key.RotationPeriod != "",
				PublicIAM:       keyPublicIAM(sc, svc, key.Name),
			}
			st.AddKMSCryptoKey(k)
		}
		return nil
	})
}

// keyPublicIAM reports whether a key's IAM policy grants a public principal. A
// read failure returns false (the rotation check still applies); it does not
// abort the walk.
func keyPublicIAM(sc *engine.ScanContext, svc *cloudkms.Service, keyName string) bool {
	policy, err := svc.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(keyName).Context(sc.Ctx).Do()
	if err != nil || policy == nil {
		return false
	}
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			if isPublicMember(m) {
				return true
			}
		}
	}
	return false
}
