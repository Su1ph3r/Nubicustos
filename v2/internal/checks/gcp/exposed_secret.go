package gcp

import (
	"fmt"
	"sort"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(exposedSecret{}) }

// exposedSecret reports credential material the GCP secrets collector (§9.2)
// found in the control plane: Cloud Function environment variables and Compute
// Engine instance metadata (including startup-scripts). Anyone with read access
// to the function config or instance metadata — a far wider set than the
// secret's intended consumers — can read these, so each is a real disclosure
// regardless of whether the credential is still live.
//
// Hits are grouped per project into one aggregate finding each, carrying only
// the masked rendering. Liveness is not asserted.
type exposedSecret struct{}

func (exposedSecret) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID:        "gcp_exposed_secret",
		Title:     "Secret material embedded in the GCP control plane",
		Provider:  "gcp",
		Service:   "secrets",
		Severity:  findings.SeverityHigh,
		Rationale: "Credentials placed in Cloud Function environment variables or Compute Engine instance metadata (e.g. startup-scripts) are readable by every principal with config/metadata-read access — a much wider audience than the secret's intended consumers — and are routinely harvested after an initial foothold.",
		Impact:    "An attacker reading the function config or instance metadata lifts the credential (service-account key, database password, API token) and uses it directly for data access or lateral movement.",
		Remediation: "Move the value into Secret Manager and reference it; rotate the exposed credential, since it must be treated as compromised:\n" +
			"gcloud secrets create ...  # then reference via --set-secrets / secret env, and rotate the leaked secret",
		References: []string{
			"https://cloud.google.com/functions/docs/configuring/secrets",
			"https://cloud.google.com/secret-manager/docs/overview",
		},
	}
}

func (c exposedSecret) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.GCP == nil || len(st.GCP.SecretHits) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()

	// Group by project so each finding is scoped to one account.
	byProject := map[string][]findings.Affected{}
	for _, h := range st.GCP.SecretHits {
		byProject[h.Account] = append(byProject[h.Account], findings.Affected{
			Type:   "secret",
			ID:     h.Resource,
			Region: h.Region,
			Detail: fmt.Sprintf("%s (%s) in %s %s [%s] at %q",
				h.Kind, h.Detector, gcpSurfaceLabel(h.Surface), h.Resource, h.Masked, h.Locator),
		})
	}

	projects := make([]string, 0, len(byProject))
	for p := range byProject {
		projects = append(projects, p)
	}
	sort.Strings(projects)

	var out []findings.Finding
	for _, project := range projects {
		items := byProject[project]
		sort.Slice(items, func(i, j int) bool {
			if items[i].Region != items[j].Region {
				return items[i].Region < items[j].Region
			}
			return items[i].ID < items[j].ID
		})
		scope := findings.Resource{
			ID: project, Name: project, Type: "gcp_project", Provider: "gcp", Account: project,
		}
		desc := fmt.Sprintf("%d secret(s) are embedded in the GCP control plane (Cloud Function env / instance metadata) in project %s. Values are shown masked; rotate each, as exposure means compromise.", len(items), project)
		out = append(out, findings.NewAggregate(c.Spec(), scope, desc, items, now))
	}
	return out, nil
}

// gcpSurfaceLabel renders a state surface id for the finding detail.
func gcpSurfaceLabel(surface string) string {
	switch surface {
	case "gcp_function_env":
		return "Cloud Function env var"
	case "gcp_instance_metadata":
		return "instance metadata"
	default:
		return surface
	}
}
