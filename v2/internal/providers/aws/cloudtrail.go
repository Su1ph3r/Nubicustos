package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&cloudtrailCollector{}) }

type cloudtrailCollector struct{}

func (cloudtrailCollector) Name() string { return "aws:cloudtrail" }

// Collect gathers CloudTrail trails across regions. A multi-region trail appears
// in every region's DescribeTrails output, so trails are deduped by ARN (the
// collector runs in a single goroutine, so a local set is safe). Logging status
// is queried in each trail's home region.
func (cloudtrailCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	seen := map[string]bool{}
	for _, region := range sc.Regions {
		client := cloudtrail.NewFromConfig(sc.AWS, func(o *cloudtrail.Options) { o.Region = region })
		out, err := client.DescribeTrails(sc.Ctx, &cloudtrail.DescribeTrailsInput{})
		if err != nil {
			continue
		}
		for _, t := range out.TrailList {
			arn := awssdk.ToString(t.TrailARN)
			if arn == "" || seen[arn] {
				continue
			}
			seen[arn] = true

			trail := state.CloudTrailTrail{
				ARN:           arn,
				Name:          awssdk.ToString(t.Name),
				HomeRegion:    awssdk.ToString(t.HomeRegion),
				MultiRegion:   awssdk.ToBool(t.IsMultiRegionTrail),
				LogValidation: awssdk.ToBool(t.LogFileValidationEnabled),
				KMSEncrypted:  awssdk.ToString(t.KmsKeyId) != "",
			}

			statusRegion := trail.HomeRegion
			if statusRegion == "" {
				statusRegion = region
			}
			sc2 := cloudtrail.NewFromConfig(sc.AWS, func(o *cloudtrail.Options) { o.Region = statusRegion })
			if status, err := sc2.GetTrailStatus(sc.Ctx, &cloudtrail.GetTrailStatusInput{Name: &arn}); err == nil {
				trail.IsLogging = awssdk.ToBool(status.IsLogging)
			}

			st.AddTrail(trail)
		}
	}
	return nil
}
