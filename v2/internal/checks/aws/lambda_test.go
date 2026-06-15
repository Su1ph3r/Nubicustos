package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestLambdaPublicChecks(t *testing.T) {
	st := state.New()
	st.AddLambdaFunction(state.LambdaFunction{Name: "open-url", Region: "us-east-1", PublicURL: true, PublicPolicy: false})
	st.AddLambdaFunction(state.LambdaFunction{Name: "open-policy", Region: "us-east-1", PublicURL: false, PublicPolicy: true})
	st.AddLambdaFunction(state.LambdaFunction{Name: "locked", Region: "us-east-1", PublicURL: false, PublicPolicy: false})

	urlFs, err := lambdaPublicURL{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(urlFs) != 1 || urlFs[0].Resource.ID != "open-url" || urlFs[0].Severity != findings.SeverityHigh {
		t.Fatalf("only the AuthType-NONE URL function should be flagged (high), got %+v", urlFs)
	}

	polFs, err := lambdaPublicPolicy{}.Evaluate(nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(polFs) != 1 || polFs[0].Resource.ID != "open-policy" {
		t.Fatalf("only the public-policy function should be flagged, got %+v", polFs)
	}
}

func TestLambdaChecksNilState(t *testing.T) {
	st := state.New()
	st.AWS = nil
	if fs, _ := (lambdaPublicURL{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
	if fs, _ := (lambdaPublicPolicy{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
}
