package aws

import (
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(messagingCollector{}) }

type messagingCollector struct{}

func (messagingCollector) Name() string { return "aws:messaging" }

// Collect gathers SNS topic and SQS queue resource policies per region and flags
// those open to a wildcard principal without a restricting condition. Per-region
// and per-resource failures are tolerated.
func (messagingCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		collectSNS(sc, region, st)
		collectSQS(sc, region, st)
	}
	return nil
}

func collectSNS(sc *engine.ScanContext, region string, st *state.State) {
	client := sns.NewFromConfig(sc.AWS, func(o *sns.Options) { o.Region = region })
	p := sns.NewListTopicsPaginator(client, &sns.ListTopicsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, t := range page.Topics {
			arn := awssdk.ToString(t.TopicArn)
			if arn == "" {
				continue
			}
			out, err := client.GetTopicAttributes(sc.Ctx, &sns.GetTopicAttributesInput{TopicArn: t.TopicArn})
			if err != nil {
				continue
			}
			st.AddMessagingResource(state.MessagingResource{
				Service:      "sns",
				Name:         arnLastSegment(arn, ":"),
				ID:           arn,
				Region:       region,
				PublicPolicy: policyTextPublic(out.Attributes["Policy"]),
			})
		}
	}
}

func collectSQS(sc *engine.ScanContext, region string, st *state.State) {
	client := sqs.NewFromConfig(sc.AWS, func(o *sqs.Options) { o.Region = region })
	p := sqs.NewListQueuesPaginator(client, &sqs.ListQueuesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, url := range page.QueueUrls {
			out, err := client.GetQueueAttributes(sc.Ctx, &sqs.GetQueueAttributesInput{
				QueueUrl:       awssdk.String(url),
				AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy},
			})
			if err != nil {
				continue
			}
			st.AddMessagingResource(state.MessagingResource{
				Service:      "sqs",
				Name:         arnLastSegment(url, "/"),
				ID:           url,
				Region:       region,
				PublicPolicy: policyTextPublic(out.Attributes["Policy"]),
			})
		}
	}
}

// policyTextPublic parses a resource-policy JSON string and reports whether it
// grants a wildcard principal with no restricting condition. An empty policy
// (the default for a new topic/queue) is not public. Reuses the condition-aware
// parser so a wildcard scoped by a SourceArn/SourceAccount condition (the normal
// cross-service pattern) is not a false positive.
func policyTextPublic(policy string) bool {
	if strings.TrimSpace(policy) == "" {
		return false
	}
	doc := parsePolicyDocument(policy)
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

// arnLastSegment returns the substring after the final sep, the human-readable
// name of a topic ARN (sep ":") or queue URL (sep "/").
func arnLastSegment(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+1:]
	}
	return s
}
