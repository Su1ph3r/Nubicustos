package aws

import (
	"net/url"
	"testing"
)

func TestParsePolicySingleStatementStringFields(t *testing.T) {
	doc := parsePolicyDocument(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Effect != "Allow" || len(s.Actions) != 1 || s.Actions[0] != "s3:GetObject" || s.Resources[0] != "*" {
		t.Fatalf("unexpected statement: %+v", s)
	}
}

func TestParsePolicyStatementArrayAndActionArray(t *testing.T) {
	doc := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","sts:AssumeRole"],"Resource":["*"]}]}`)
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	if len(doc.Statements[0].Actions) != 2 {
		t.Fatalf("expected 2 actions, got %v", doc.Statements[0].Actions)
	}
}

func TestParsePolicyPrincipalWildcard(t *testing.T) {
	doc := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`)
	p := doc.Statements[0]
	if len(p.AWSPrincipals) != 1 || p.AWSPrincipals[0] != "*" {
		t.Fatalf("expected wildcard principal, got %+v", p.AWSPrincipals)
	}
}

func TestParsePolicyPrincipalObject(t *testing.T) {
	doc := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222233334444:root","Federated":"arn:aws:iam::111:oidc-provider/token.actions.githubusercontent.com","Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	p := doc.Statements[0]
	if len(p.AWSPrincipals) != 1 || p.AWSPrincipals[0] != "arn:aws:iam::222233334444:root" {
		t.Fatalf("AWS principal not parsed: %+v", p.AWSPrincipals)
	}
	if len(p.Federated) != 1 || p.Services[0] != "ec2.amazonaws.com" {
		t.Fatalf("federated/service not parsed: %+v / %+v", p.Federated, p.Services)
	}
}

func TestParsePolicyConditionKeys(t *testing.T) {
	doc := parsePolicyDocument(`{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:...:oidc-provider/x"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"x:aud":"sts.amazonaws.com","x:sub":"repo:org/repo:ref:refs/heads/main"}}}]}`)
	keys := doc.Statements[0].ConditionKeys
	if len(keys) != 2 {
		t.Fatalf("expected 2 condition keys, got %v", keys)
	}
}

func TestParsePolicyURLEncoded(t *testing.T) {
	plain := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	encoded := url.PathEscape(plain)
	doc := parsePolicyDocument(encoded)
	if len(doc.Statements) != 1 || doc.Statements[0].Actions[0] != "*" {
		t.Fatalf("URL-encoded document did not round-trip: %+v", doc)
	}
}

func TestParsePolicyMalformedIsEmpty(t *testing.T) {
	if doc := parsePolicyDocument("not json"); len(doc.Statements) != 0 {
		t.Fatalf("malformed document should yield no statements, got %+v", doc)
	}
	if doc := parsePolicyDocument(""); len(doc.Statements) != 0 {
		t.Fatalf("empty document should yield no statements")
	}
}
