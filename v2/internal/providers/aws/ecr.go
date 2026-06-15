package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(ecrCollector{}) }

type ecrCollector struct{}

func (ecrCollector) Name() string { return "aws:ecr" }

// Collect gathers ECR repository posture per region: scan-on-push and whether
// the repository policy grants public access. Per-region/repo failures are
// tolerated.
func (ecrCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := ecr.NewFromConfig(sc.AWS, func(o *ecr.Options) { o.Region = region })
		p := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, repo := range page.Repositories {
				name := awssdk.ToString(repo.RepositoryName)
				if name == "" {
					continue
				}
				scanOnPush := repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush
				st.AddECRRepository(state.ECRRepository{
					Name:         name,
					Region:       region,
					ScanOnPush:   scanOnPush,
					PublicPolicy: ecrRepoPolicyPublic(sc, client, name),
				})
			}
		}
	}
	return nil
}

// ecrRepoPolicyPublic reports whether a repository policy grants a wildcard
// principal with no restricting condition. Absence of a policy is not public.
func ecrRepoPolicyPublic(sc *engine.ScanContext, client *ecr.Client, name string) bool {
	out, err := client.GetRepositoryPolicy(sc.Ctx, &ecr.GetRepositoryPolicyInput{RepositoryName: awssdk.String(name)})
	if err != nil || out == nil || out.PolicyText == nil {
		return false
	}
	return policyTextPublic(awssdk.ToString(out.PolicyText))
}
