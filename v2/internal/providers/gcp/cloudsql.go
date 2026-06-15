package gcp

import (
	"errors"
	"fmt"

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(cloudSQLCollector{}) }

type cloudSQLCollector struct{}

func (cloudSQLCollector) Name() string { return "gcp:cloudsql" }

// Collect gathers Cloud SQL instance posture across the in-scope projects:
// public-IP exposure, SSL enforcement, automated backups, and authorized
// networks open to the internet.
func (cloudSQLCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := sqladmin.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp cloudsql: building client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		call := svc.Instances.List(project)
		for {
			resp, err := call.Context(sc.Ctx).Do()
			if err != nil {
				errs = append(errs, fmt.Errorf("gcp cloudsql: listing instances in project %s: %w", project, err))
				break
			}
			for _, di := range resp.Items {
				if di == nil {
					continue
				}
				st.AddCloudSQLInstance(normalizeCloudSQL(project, di))
			}
			if resp.NextPageToken == "" {
				break
			}
			call = svc.Instances.List(project).PageToken(resp.NextPageToken)
		}
	}
	return errors.Join(errs...)
}

func normalizeCloudSQL(project string, di *sqladmin.DatabaseInstance) state.CloudSQLInstance {
	out := state.CloudSQLInstance{
		Name:    di.Name,
		Project: project,
		Region:  di.Region,
		Version: di.DatabaseVersion,
	}
	if s := di.Settings; s != nil {
		if ip := s.IpConfiguration; ip != nil {
			out.PublicIP = ip.Ipv4Enabled
			// RequireSsl is deprecated in favor of SslMode; treat either encrypted-
			// required mode as enforcing SSL.
			out.RequireSSL = ip.RequireSsl ||
				ip.SslMode == "ENCRYPTED_ONLY" ||
				ip.SslMode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
			for _, n := range ip.AuthorizedNetworks {
				if n != nil && n.Value != "" {
					out.AuthorizedNetworks = append(out.AuthorizedNetworks, n.Value)
				}
			}
		}
		out.BackupEnabled = s.BackupConfiguration != nil && s.BackupConfiguration.Enabled
	}
	return out
}
