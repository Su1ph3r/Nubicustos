// Package aws contains AWS collectors: read-only gatherers that populate
// state from the AWS APIs. Collectors do no judgement — that is the checks'
// job. They register themselves with the engine at init time.
package aws

import (
	"errors"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&s3Collector{}) }

type s3Collector struct{}

func (s3Collector) Name() string { return "aws:s3" }

// Collect lists buckets and gathers each one's public-access posture: the
// Public Access Block configuration, whether the ACL grants public access, and
// whether the bucket policy evaluates as public.
func (s3Collector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	client := s3.NewFromConfig(sc.AWS)

	list, err := client.ListBuckets(sc.Ctx, &s3.ListBucketsInput{})
	if err != nil {
		return err
	}

	for _, b := range list.Buckets {
		name := awssdk.ToString(b.Name)
		if name == "" {
			continue
		}
		region := bucketRegion(sc, client, name)
		// Per-bucket calls must target the bucket's own region.
		rc := s3.NewFromConfig(sc.AWS, func(o *s3.Options) { o.Region = region })

		bucket := state.S3Bucket{Name: name, Region: region}
		applyPublicAccessBlock(sc, rc, name, &bucket)
		bucket.ACLPublic = aclIsPublic(sc, rc, name)
		bucket.PolicyPublic = policyIsPublic(sc, rc, name)

		st.AddS3Bucket(bucket)
	}
	return nil
}

// bucketRegion resolves a bucket's region; the API returns an empty constraint
// for us-east-1.
func bucketRegion(sc *engine.ScanContext, client *s3.Client, name string) string {
	out, err := client.GetBucketLocation(sc.Ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(name)})
	if err != nil || out.LocationConstraint == "" {
		return "us-east-1"
	}
	return string(out.LocationConstraint)
}

// applyPublicAccessBlock records the bucket's PAB configuration. A missing
// configuration is itself risk, so HasPublicAccessBlock stays false there.
func applyPublicAccessBlock(sc *engine.ScanContext, client *s3.Client, name string, bucket *state.S3Bucket) {
	out, err := client.GetPublicAccessBlock(sc.Ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(name)})
	if err != nil {
		// NoSuchPublicAccessBlockConfiguration => no PAB at all.
		return
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return
	}
	bucket.HasPublicAccessBlock = true
	bucket.BlockPublicAcls = awssdk.ToBool(cfg.BlockPublicAcls)
	bucket.IgnorePublicAcls = awssdk.ToBool(cfg.IgnorePublicAcls)
	bucket.BlockPublicPolicy = awssdk.ToBool(cfg.BlockPublicPolicy)
	bucket.RestrictPublicBuckets = awssdk.ToBool(cfg.RestrictPublicBuckets)
}

// aclIsPublic reports whether the bucket ACL grants any permission to the
// AllUsers or AuthenticatedUsers groups.
func aclIsPublic(sc *engine.ScanContext, client *s3.Client, name string) bool {
	out, err := client.GetBucketAcl(sc.Ctx, &s3.GetBucketAclInput{Bucket: awssdk.String(name)})
	if err != nil {
		return false
	}
	for _, g := range out.Grants {
		if g.Grantee == nil || g.Grantee.Type != s3types.TypeGroup {
			continue
		}
		uri := awssdk.ToString(g.Grantee.URI)
		if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
			return true
		}
	}
	return false
}

// policyIsPublic reports whether the bucket policy evaluates as public. Absence
// of a policy is treated as not-public.
func policyIsPublic(sc *engine.ScanContext, client *s3.Client, name string) bool {
	out, err := client.GetBucketPolicyStatus(sc.Ctx, &s3.GetBucketPolicyStatusInput{Bucket: awssdk.String(name)})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			// NoSuchBucketPolicy and friends => not public.
			return false
		}
		return false
	}
	return out.PolicyStatus != nil && awssdk.ToBool(out.PolicyStatus.IsPublic)
}
