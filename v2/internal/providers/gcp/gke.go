package gcp

import (
	"errors"
	"fmt"

	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(gkeCollector{}) }

type gkeCollector struct{}

func (gkeCollector) Name() string { return "gcp:gke" }

// Collect gathers GKE cluster posture across the in-scope projects: legacy ABAC,
// network-policy enforcement, and whether control-plane access is restricted to
// authorized networks. Clusters in every location are listed with the "-"
// wildcard parent.
func (gkeCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := container.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp gke: building client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		parent := "projects/" + project + "/locations/-"
		resp, err := svc.Projects.Locations.Clusters.List(parent).Context(sc.Ctx).Do()
		if err != nil {
			errs = append(errs, fmt.Errorf("gcp gke: listing clusters in project %s: %w", project, err))
			continue
		}
		for _, c := range resp.Clusters {
			if c == nil {
				continue
			}
			st.AddGKECluster(state.GKECluster{
				Name:                     c.Name,
				Project:                  project,
				Location:                 c.Location,
				LegacyABAC:               c.LegacyAbac != nil && c.LegacyAbac.Enabled,
				NetworkPolicyEnabled:     c.NetworkPolicy != nil && c.NetworkPolicy.Enabled,
				MasterAuthorizedNetworks: c.MasterAuthorizedNetworksConfig != nil && c.MasterAuthorizedNetworksConfig.Enabled,
			})
		}
	}
	return errors.Join(errs...)
}
