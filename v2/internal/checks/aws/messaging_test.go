package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestMessagingPublicPolicyChecks(t *testing.T) {
	st := state.New()
	st.AddMessagingResource(state.MessagingResource{Service: "sns", Name: "open-topic", ID: "arn:aws:sns:us-east-1:1:open-topic", Region: "us-east-1", PublicPolicy: true})
	st.AddMessagingResource(state.MessagingResource{Service: "sns", Name: "private-topic", ID: "arn:aws:sns:us-east-1:1:private-topic", Region: "us-east-1", PublicPolicy: false})
	st.AddMessagingResource(state.MessagingResource{Service: "sqs", Name: "open-queue", ID: "https://sqs.us-east-1.amazonaws.com/1/open-queue", Region: "us-east-1", PublicPolicy: true})

	snsFs, _ := snsPublicPolicy{}.Evaluate(nil, st)
	if len(snsFs) != 1 || snsFs[0].Resource.Name != "open-topic" || snsFs[0].Severity != findings.SeverityHigh {
		t.Fatalf("only the public SNS topic should be flagged (high), got %+v", snsFs)
	}
	sqsFs, _ := sqsPublicPolicy{}.Evaluate(nil, st)
	if len(sqsFs) != 1 || sqsFs[0].Resource.Name != "open-queue" {
		t.Fatalf("only the public SQS queue should be flagged, got %+v", sqsFs)
	}
}

func TestMessagingNilState(t *testing.T) {
	st := state.New()
	st.AWS = nil
	if fs, _ := (snsPublicPolicy{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
}
