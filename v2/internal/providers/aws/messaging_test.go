package aws

import "testing"

func TestPolicyTextPublic(t *testing.T) {
	// Empty policy (the default for a new topic/queue) → not public.
	if policyTextPublic("") {
		t.Error("empty policy must not be public")
	}
	// Wildcard principal, no condition → public.
	open := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Resource":"*"}]}`
	if !policyTextPublic(open) {
		t.Error("wildcard principal with no condition must be public")
	}
	// Wildcard principal scoped by a condition → NOT public (the normal cross-
	// service trigger pattern).
	scoped := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::my-bucket"}}}]}`
	if policyTextPublic(scoped) {
		t.Error("condition-scoped wildcard must NOT be flagged public")
	}
}

func TestArnLastSegment(t *testing.T) {
	if got := arnLastSegment("arn:aws:sns:us-east-1:123:my-topic", ":"); got != "my-topic" {
		t.Errorf("topic name = %q, want my-topic", got)
	}
	if got := arnLastSegment("https://sqs.us-east-1.amazonaws.com/123/my-queue", "/"); got != "my-queue" {
		t.Errorf("queue name = %q, want my-queue", got)
	}
}
