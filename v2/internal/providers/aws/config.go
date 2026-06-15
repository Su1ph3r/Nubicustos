package aws

import (
	configservice "github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&configCollector{}) }

type configCollector struct{}

func (configCollector) Name() string { return "aws:config" }

// Collect records, per region, whether AWS Config has a recorder that is
// actively recording all supported resource types. An entry is written for
// every scanned region (defaulting to not-recording) so the check knows which
// regions were examined.
func (configCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := configservice.NewFromConfig(sc.AWS, func(o *configservice.Options) { o.Region = region })

		status := state.ConfigStatus{}

		recorders, err := client.DescribeConfigurationRecorders(sc.Ctx, &configservice.DescribeConfigurationRecordersInput{})
		if err != nil {
			st.SetConfigStatus(region, status)
			continue
		}
		for _, r := range recorders.ConfigurationRecorders {
			if r.RecordingGroup != nil && r.RecordingGroup.AllSupported {
				status.AllSupported = true
			}
		}

		recStatus, err := client.DescribeConfigurationRecorderStatus(sc.Ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
		if err == nil {
			for _, s := range recStatus.ConfigurationRecordersStatus {
				if s.Recording {
					status.Recording = true
				}
			}
		}

		st.SetConfigStatus(region, status)
	}
	return nil
}
