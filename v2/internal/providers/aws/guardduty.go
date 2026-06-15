package aws

import (
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&guarddutyCollector{}) }

type guarddutyCollector struct{}

func (guarddutyCollector) Name() string { return "aws:guardduty" }

// Collect records, per region, whether GuardDuty has at least one enabled
// detector. An entry is written for every scanned region (defaulting to false)
// so the check knows which regions were examined.
func (guarddutyCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := guardduty.NewFromConfig(sc.AWS, func(o *guardduty.Options) { o.Region = region })

		enabled := false
		if list, err := client.ListDetectors(sc.Ctx, &guardduty.ListDetectorsInput{}); err == nil {
			for _, id := range list.DetectorIds {
				det, err := client.GetDetector(sc.Ctx, &guardduty.GetDetectorInput{DetectorId: &id})
				if err == nil && det.Status == gdtypes.DetectorStatusEnabled {
					enabled = true
					break
				}
			}
		}
		st.SetGuardDuty(region, enabled)
	}
	return nil
}
