package gcp

import (
	"errors"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(computeCollector{}) }

type computeCollector struct{}

func (computeCollector) Name() string { return "gcp:compute" }

// Collect gathers Compute Engine VM posture across the in-scope projects: public
// IP exposure, Shielded VM, default-service-account full-API access, interactive
// serial console, and IP forwarding.
func (computeCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := compute.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp compute: building client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		listErr := svc.Instances.AggregatedList(project).Pages(sc.Ctx,
			func(page *compute.InstanceAggregatedList) error {
				for _, scoped := range page.Items {
					for _, inst := range scoped.Instances {
						if inst == nil {
							continue
						}
						st.AddComputeInstance(normalizeComputeVM(project, inst))
					}
				}
				return nil
			})
		if listErr != nil {
			errs = append(errs, fmt.Errorf("gcp compute: listing instances in project %s: %w", project, listErr))
		}
	}
	return errors.Join(errs...)
}

func normalizeComputeVM(project string, inst *compute.Instance) state.ComputeInstance {
	out := state.ComputeInstance{
		Name:         inst.Name,
		Project:      project,
		Zone:         zoneShort(inst.Zone),
		CanIPForward: inst.CanIpForward,
	}
	for _, ni := range inst.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac != nil && ac.NatIP != "" {
				out.HasPublicIP = true
			}
		}
	}
	if s := inst.ShieldedInstanceConfig; s != nil {
		out.ShieldedVM = s.EnableSecureBoot && s.EnableVtpm && s.EnableIntegrityMonitoring
	}
	for _, sa := range inst.ServiceAccounts {
		if sa == nil {
			continue
		}
		if isDefaultComputeSA(sa.Email) && hasCloudPlatformScope(sa.Scopes) {
			out.DefaultSAFullAPI = true
		}
	}
	if inst.Metadata != nil {
		for _, item := range inst.Metadata.Items {
			if item != nil && item.Key == "serial-port-enable" && item.Value != nil &&
				strings.EqualFold(strings.TrimSpace(*item.Value), "true") {
				out.SerialPortEnabled = true
			}
		}
	}
	return out
}

// isDefaultComputeSA reports whether email is a project's default Compute Engine
// service account (e.g. 123456789-compute@developer.gserviceaccount.com).
func isDefaultComputeSA(email string) bool {
	return strings.HasSuffix(email, "-compute@developer.gserviceaccount.com")
}

// hasCloudPlatformScope reports whether the scopes grant the full cloud-platform
// API surface — the broadest grant, well beyond what most VMs need.
func hasCloudPlatformScope(scopes []string) bool {
	for _, s := range scopes {
		if s == "https://www.googleapis.com/auth/cloud-platform" {
			return true
		}
	}
	return false
}
