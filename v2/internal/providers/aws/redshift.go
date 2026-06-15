package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(redshiftCollector{}) }

type redshiftCollector struct{}

func (redshiftCollector) Name() string { return "aws:redshift" }

// Collect gathers Redshift cluster posture per region: public accessibility and
// at-rest encryption. Per-region failures are tolerated.
func (redshiftCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := redshift.NewFromConfig(sc.AWS, func(o *redshift.Options) { o.Region = region })
		p := redshift.NewDescribeClustersPaginator(client, &redshift.DescribeClustersInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, c := range page.Clusters {
				id := awssdk.ToString(c.ClusterIdentifier)
				if id == "" {
					continue
				}
				st.AddRedshiftCluster(state.RedshiftCluster{
					ID:        id,
					Region:    region,
					Public:    awssdk.ToBool(c.PubliclyAccessible),
					Encrypted: awssdk.ToBool(c.Encrypted),
				})
			}
		}
	}
	return nil
}
