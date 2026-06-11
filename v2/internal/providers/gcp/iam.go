package gcp

import (
	"errors"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(iamCollector{}) }

type iamCollector struct{}

func (iamCollector) Name() string { return "gcp:iam" }

// Collect gathers each in-scope project's IAM policy bindings so the checks can
// flag public members and over-broad primitive roles.
func (iamCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := cloudresourcemanager.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return err
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		policy, err := svc.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Context(sc.Ctx).Do()
		if err != nil {
			// Tolerate a denied project, but surface it — an unread IAM policy must
			// not read as a project with no public/primitive bindings.
			errs = append(errs, fmt.Errorf("gcp iam: getIamPolicy for project %s: %w", project, err))
			continue
		}
		for _, b := range policy.Bindings {
			st.AddGCPIAMBinding(state.GCPIAMBinding{
				Project: project,
				Role:    b.Role,
				Members: b.Members,
			})
		}
	}
	return errors.Join(errs...)
}
