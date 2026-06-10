package aws

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EnabledRegions returns the regions that are enabled (or opted-in) for the
// account. DescribeRegions defaults to enabled-only, so a full posture scan can
// iterate every region the account actually uses.
func EnabledRegions(ctx context.Context, cfg awssdk.Config) ([]string, error) {
	out, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}
	return regions, nil
}
