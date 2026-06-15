package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(lambdaPublicURL{})
	engine.RegisterCheck(lambdaPublicPolicy{})
}

func lambdaResource(f state.LambdaFunction) findings.Resource {
	return findings.Resource{
		ID: f.Name, Name: f.Name, Type: "aws_lambda_function", Provider: "aws", Region: f.Region,
	}
}

type lambdaPublicURL struct{}

func (lambdaPublicURL) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_lambda_public_function_url", Title: "Lambda function URL allows anonymous (unauthenticated) invocation",
		Provider: "aws", Service: "lambda", Severity: findings.SeverityHigh,
		Rationale:   "A function URL with AuthType NONE is invocable by anyone on the internet over HTTPS with no IAM authentication, exposing the function's logic and any data it can reach.",
		Impact:      "An unauthenticated attacker can invoke the function directly, exercising its code paths and downstream access.",
		Remediation: "Require IAM auth on the URL: aws lambda update-function-url-config --function-name <name> --auth-type AWS_IAM",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-API"}},
	}
}

func (c lambdaPublicURL) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, f := range st.AWS.Lambdas {
		if !f.PublicURL {
			continue
		}
		desc := fmt.Sprintf("Lambda function %q (%s) has a function URL with AuthType NONE (anonymous invoke).", f.Name, f.Region)
		poc := fmt.Sprintf("aws lambda get-function-url-config --function-name %s --region %s --query AuthType", f.Name, f.Region)
		out = append(out, findings.New(c.Spec(), lambdaResource(f), desc, poc, now))
	}
	return out, nil
}

type lambdaPublicPolicy struct{}

func (lambdaPublicPolicy) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_lambda_public_resource_policy", Title: "Lambda resource policy grants public invoke",
		Provider: "aws", Service: "lambda", Severity: findings.SeverityHigh,
		Rationale:   "A resource policy allowing Principal \"*\" with no restricting condition lets any AWS account (or anonymous caller, depending on the action) invoke or manage the function.",
		Impact:      "External principals can invoke the function or alter its configuration, bypassing the account boundary.",
		Remediation: "Scope or remove the wildcard statement, or add a SourceArn/SourceAccount condition: aws lambda remove-permission --function-name <name> --statement-id <sid>",
		Compliance:  []findings.ComplianceRef{{Framework: "AWS Well-Architected", Control: "SEC-API"}},
	}
}

func (c lambdaPublicPolicy) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, f := range st.AWS.Lambdas {
		if !f.PublicPolicy {
			continue
		}
		desc := fmt.Sprintf("Lambda function %q (%s) has a resource policy granting a wildcard principal with no condition.", f.Name, f.Region)
		poc := fmt.Sprintf("aws lambda get-policy --function-name %s --region %s --query Policy", f.Name, f.Region)
		out = append(out, findings.New(c.Spec(), lambdaResource(f), desc, poc, now))
	}
	return out, nil
}
