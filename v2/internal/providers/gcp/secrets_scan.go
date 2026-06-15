package gcp

import (
	"errors"
	"fmt"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(secretsScanCollector{}) }

// secretsScanCollector scans the GCP control plane for embedded credentials
// (plan §9.2), extending the cloud-side secrets capability to GCP. Two of the
// richest surfaces are covered:
//
//   - Cloud Functions environment variables — the GCP equivalent of Lambda env
//     vars, run through the shared key/value detector.
//   - Compute Engine instance metadata — startup-scripts and other metadata
//     values, scanned as free text (this is where service-account keys, database
//     URLs, and API tokens are routinely baked into bootstrap scripts).
//
// Only the masked detection — never the raw value — is recorded. Per-project and
// per-API failures are tolerated so one inaccessible project or disabled API
// never blanks the rest.
type secretsScanCollector struct{}

func (secretsScanCollector) Name() string { return "gcp:secrets-scan" }

func (c secretsScanCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	var errs []error
	if err := c.scanFunctions(sc, st); err != nil {
		errs = append(errs, err)
	}
	if err := c.scanInstanceMetadata(sc, st); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// scanFunctions runs the key/value detector over every Cloud Function's
// environment variables across the in-scope projects.
func (secretsScanCollector) scanFunctions(sc *engine.ScanContext, st *state.State) error {
	svc, err := cloudfunctions.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp secrets: building functions client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		parent := "projects/" + project + "/locations/-" // "-" = all locations
		listErr := svc.Projects.Locations.Functions.List(parent).Pages(sc.Ctx,
			func(page *cloudfunctions.ListFunctionsResponse) error {
				for _, fn := range page.Functions {
					name := shortResourceName(fn.Name)
					for k, v := range fn.EnvironmentVariables {
						for _, m := range secrets.ScanKeyValue(k, v, k) {
							st.AddGCPSecretHit(gcpSecretHit(m, "gcp_function_env", name, project, regionFromFunction(fn.Name), k))
						}
					}
				}
				return nil
			})
		if listErr != nil {
			errs = append(errs, fmt.Errorf("gcp secrets: listing functions in project %s: %w", project, listErr))
		}
	}
	return errors.Join(errs...)
}

// scanInstanceMetadata scans Compute Engine instance metadata values (including
// startup-scripts) as free text across the in-scope projects.
func (secretsScanCollector) scanInstanceMetadata(sc *engine.ScanContext, st *state.State) error {
	svc, err := compute.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp secrets: building compute client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		listErr := svc.Instances.AggregatedList(project).Pages(sc.Ctx,
			func(page *compute.InstanceAggregatedList) error {
				for _, scoped := range page.Items {
					for _, inst := range scoped.Instances {
						if inst.Metadata == nil {
							continue
						}
						for _, item := range inst.Metadata.Items {
							if item == nil || item.Value == nil {
								continue
							}
							for _, m := range secrets.Scan(*item.Value, item.Key) {
								st.AddGCPSecretHit(gcpSecretHit(m, "gcp_instance_metadata", inst.Name, project, zoneShort(inst.Zone), item.Key))
							}
						}
					}
				}
				return nil
			})
		if listErr != nil {
			errs = append(errs, fmt.Errorf("gcp secrets: listing instances in project %s: %w", project, listErr))
		}
	}
	return errors.Join(errs...)
}

// gcpSecretHit folds a detector Match plus its GCP source into a state record.
func gcpSecretHit(m secrets.Match, surface, resource, project, region, locator string) state.SecretHit {
	return state.SecretHit{
		Detector: m.Detector,
		Kind:     m.Kind,
		Surface:  surface,
		Resource: resource,
		Account:  project,
		Region:   region,
		Locator:  locator,
		Masked:   m.Masked,
		LastFour: m.LastFour,
		Entropy:  m.Entropy,
	}
}
