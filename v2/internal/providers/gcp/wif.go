package gcp

import (
	"errors"
	"fmt"

	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(wifCollector{}) }

type wifCollector struct{}

func (wifCollector) Name() string { return "gcp:wif" }

// Collect enumerates each in-scope project's workload-identity pools and their
// providers, recording the external identity source each provider trusts (an AWS
// account, an OIDC issuer, or a SAML IdP). This is the GCP side of cross-cloud
// federation: a provider whose issuer is AWS or Azure lets a workload in that
// cloud federate into GCP and impersonate service accounts.
//
// Pools live under the "global" location. A denied project is tolerated but
// surfaced, so an unread project never reads as "no external federation."
func (wifCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := iam.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return err
	}

	var errs []error
	for _, project := range sc.GCP.Projects {
		parent := fmt.Sprintf("projects/%s/locations/global", project)
		poolsCall := svc.Projects.Locations.WorkloadIdentityPools.List(parent)
		err := poolsCall.Pages(sc.Ctx, func(page *iam.ListWorkloadIdentityPoolsResponse) error {
			for _, pool := range page.WorkloadIdentityPools {
				poolID := lastSegment(pool.Name)
				poolInactive := pool.Disabled || (pool.State != "" && pool.State != "ACTIVE")
				if err := collectProviders(sc, svc, project, pool.Name, poolID, poolInactive, st); err != nil {
					errs = append(errs, err)
				}
			}
			return nil
		})
		if err != nil {
			// A project without the WIF API enabled, or a denied list, is tolerated
			// but surfaced rather than silently treated as "no federation".
			errs = append(errs, fmt.Errorf("gcp wif: list pools for project %s: %w", project, err))
		}
	}
	return errors.Join(errs...)
}

// collectProviders lists and records the providers of one pool.
func collectProviders(sc *engine.ScanContext, svc *iam.Service, project, poolName, poolID string, poolInactive bool, st *state.State) error {
	call := svc.Projects.Locations.WorkloadIdentityPools.Providers.List(poolName)
	return call.Pages(sc.Ctx, func(page *iam.ListWorkloadIdentityPoolProvidersResponse) error {
		for _, p := range page.WorkloadIdentityPoolProviders {
			rec := state.GCPWorkloadIdentityProvider{
				Project:  project,
				Pool:     poolID,
				Provider: lastSegment(p.Name),
				Disabled: poolInactive || p.Disabled || (p.State != "" && p.State != "ACTIVE"),
			}
			switch {
			case p.Aws != nil:
				rec.Kind = "aws"
				rec.AWSAccount = p.Aws.AccountId
			case p.Oidc != nil:
				rec.Kind = "oidc"
				rec.Issuer = p.Oidc.IssuerUri
			case p.Saml != nil:
				rec.Kind = "saml"
			default:
				continue // no recognized external source on this provider
			}
			st.AddGCPWorkloadIdentityProvider(rec)
		}
		return nil
	})
}
