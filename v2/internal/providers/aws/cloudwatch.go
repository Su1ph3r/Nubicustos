package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(cloudWatchCollector{}) }

type cloudWatchCollector struct{}

func (cloudWatchCollector) Name() string { return "aws:cloudwatch" }

// Collect gathers the CloudWatch Logs metric filters and the metrics that have
// alarms across regions, so the monitoring check can verify CIS log-metric-
// filter + alarm coverage for sensitive events. Per-region failures are
// tolerated.
func (cloudWatchCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		collectMetricFilters(sc, region, st)
		collectAlarms(sc, region, st)
	}
	return nil
}

func collectMetricFilters(sc *engine.ScanContext, region string, st *state.State) {
	client := cloudwatchlogs.NewFromConfig(sc.AWS, func(o *cloudwatchlogs.Options) { o.Region = region })
	p := cloudwatchlogs.NewDescribeMetricFiltersPaginator(client, &cloudwatchlogs.DescribeMetricFiltersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, mf := range page.MetricFilters {
			f := state.LogMetricFilter{Pattern: awssdk.ToString(mf.FilterPattern), Region: region}
			for _, tr := range mf.MetricTransformations {
				if n := awssdk.ToString(tr.MetricName); n != "" {
					f.MetricNames = append(f.MetricNames, n)
				}
			}
			st.AddLogMetricFilter(f)
		}
	}
}

func collectAlarms(sc *engine.ScanContext, region string, st *state.State) {
	client := cloudwatch.NewFromConfig(sc.AWS, func(o *cloudwatch.Options) { o.Region = region })
	p := cloudwatch.NewDescribeAlarmsPaginator(client, &cloudwatch.DescribeAlarmsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, a := range page.MetricAlarms {
			if n := awssdk.ToString(a.MetricName); n != "" {
				st.AddAlarmedMetric(n)
			}
		}
	}
}
