package azure

import (
	"errors"
	"fmt"

	armmysql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	armpostgres "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(rdbmsCollector{}) }

type rdbmsCollector struct{}

func (rdbmsCollector) Name() string { return "azure:rdbms" }

// Collect gathers Azure Database flexible-server posture (MySQL + PostgreSQL)
// across the in-scope subscriptions: whether public network access is enabled.
// Per-subscription failures are tolerated.
func (rdbmsCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "azure" || sc.Azure.Credential == nil {
		return nil
	}
	var errs []error
	for _, sub := range sc.Azure.Subscriptions {
		if err := collectMySQL(sc, st, sub); err != nil {
			errs = append(errs, err)
		}
		if err := collectPostgres(sc, st, sub); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func collectMySQL(sc *engine.ScanContext, st *state.State, sub string) error {
	client, err := armmysql.NewServersClient(sub, sc.Azure.Credential, nil)
	if err != nil {
		return fmt.Errorf("azure rdbms: mysql client for %s: %w", sub, err)
	}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return fmt.Errorf("azure rdbms: listing mysql servers in %s: %w", sub, err)
		}
		for _, srv := range page.Value {
			if srv == nil {
				continue
			}
			d := state.AzureDBFlexServer{
				Engine: "mysql", Name: str(srv.Name), ResourceGroup: resourceGroupFromID(str(srv.ID)),
				Subscription: sub, Location: str(srv.Location),
			}
			if p := srv.Properties; p != nil && p.Network != nil && p.Network.PublicNetworkAccess != nil {
				d.PublicNetworkAccess = string(*p.Network.PublicNetworkAccess) == "Enabled"
			}
			st.AddAzureDBFlexServer(d)
		}
	}
	return nil
}

func collectPostgres(sc *engine.ScanContext, st *state.State, sub string) error {
	client, err := armpostgres.NewServersClient(sub, sc.Azure.Credential, nil)
	if err != nil {
		return fmt.Errorf("azure rdbms: postgres client for %s: %w", sub, err)
	}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return fmt.Errorf("azure rdbms: listing postgres servers in %s: %w", sub, err)
		}
		for _, srv := range page.Value {
			if srv == nil {
				continue
			}
			d := state.AzureDBFlexServer{
				Engine: "postgresql", Name: str(srv.Name), ResourceGroup: resourceGroupFromID(str(srv.ID)),
				Subscription: sub, Location: str(srv.Location),
			}
			if p := srv.Properties; p != nil && p.Network != nil && p.Network.PublicNetworkAccess != nil {
				d.PublicNetworkAccess = string(*p.Network.PublicNetworkAccess) == "Enabled"
			}
			st.AddAzureDBFlexServer(d)
		}
	}
	return nil
}
