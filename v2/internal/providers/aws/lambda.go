package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(lambdaCollector{}) }

type lambdaCollector struct{}

func (lambdaCollector) Name() string { return "aws:lambda" }

// Collect gathers Lambda public-exposure posture per region: a function URL with
// AuthType NONE (anonymous HTTPS invoke) and a resource policy that grants
// Principal "*" without a restricting condition. Per-region/function failures are
// tolerated so one denied region or function never blanks the rest.
func (lambdaCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := lambda.NewFromConfig(sc.AWS, func(o *lambda.Options) { o.Region = region })
		p := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, fn := range page.Functions {
				name := awssdk.ToString(fn.FunctionName)
				if name == "" {
					continue
				}
				st.AddLambdaFunction(state.LambdaFunction{
					Name:         name,
					Region:       region,
					PublicURL:    functionURLPublic(sc, client, name),
					PublicPolicy: functionPolicyPublic(sc, client, name),
				})
			}
		}
	}
	return nil
}

// functionURLPublic reports whether the function has a URL config with AuthType
// NONE (anonymous). Absence of a URL config (ResourceNotFound) is not public.
func functionURLPublic(sc *engine.ScanContext, client *lambda.Client, name string) bool {
	out, err := client.GetFunctionUrlConfig(sc.Ctx, &lambda.GetFunctionUrlConfigInput{FunctionName: awssdk.String(name)})
	if err != nil || out == nil {
		return false
	}
	return out.AuthType == lambdatypes.FunctionUrlAuthTypeNone
}

// functionPolicyPublic reports whether the function's resource policy grants a
// wildcard principal with no restricting condition. A wildcard principal that IS
// condition-scoped (e.g. a service trigger gated by AWS:SourceArn) is the normal,
// safe pattern and is not flagged — mirroring the trust analyzer's nuance.
func functionPolicyPublic(sc *engine.ScanContext, client *lambda.Client, name string) bool {
	out, err := client.GetPolicy(sc.Ctx, &lambda.GetPolicyInput{FunctionName: awssdk.String(name)})
	if err != nil || out == nil || out.Policy == nil {
		return false
	}
	doc := parsePolicyDocument(awssdk.ToString(out.Policy))
	for _, stmt := range doc.Statements {
		if stmt.Effect != "Allow" {
			continue
		}
		for _, pr := range stmt.AWSPrincipals {
			if pr == "*" && len(stmt.ConditionKeys) == 0 {
				return true
			}
		}
	}
	return false
}
