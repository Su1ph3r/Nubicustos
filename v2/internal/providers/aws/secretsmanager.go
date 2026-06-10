package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&secretsCollector{}) }

type secretsCollector struct{}

func (secretsCollector) Name() string { return "aws:secretsmanager" }

// Collect lists Secrets Manager secrets per region and records whether each has
// automatic rotation enabled.
func (secretsCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := secretsmanager.NewFromConfig(sc.AWS, func(o *secretsmanager.Options) { o.Region = region })
		pager := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, s := range page.SecretList {
				st.AddSecret(state.SecretInfo{
					ARN:             awssdk.ToString(s.ARN),
					Name:            awssdk.ToString(s.Name),
					Region:          region,
					RotationEnabled: awssdk.ToBool(s.RotationEnabled),
				})
			}
		}
	}
	return nil
}
