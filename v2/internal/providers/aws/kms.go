package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&kmsCollector{}) }

type kmsCollector struct{}

func (kmsCollector) Name() string { return "aws:kms" }

// Collect gathers customer-managed KMS keys and their rotation status across
// regions. AWS-managed keys are skipped (they rotate automatically and cannot
// be configured). Keys whose rotation status cannot be read (e.g. asymmetric
// keys, which do not support rotation) are skipped rather than guessed.
func (kmsCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := kms.NewFromConfig(sc.AWS, func(o *kms.Options) { o.Region = region })
		pager := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, entry := range page.Keys {
				keyID := awssdk.ToString(entry.KeyId)
				meta, err := client.DescribeKey(sc.Ctx, &kms.DescribeKeyInput{KeyId: &keyID})
				if err != nil || meta.KeyMetadata == nil {
					continue
				}
				m := meta.KeyMetadata
				if m.KeyManager != kmstypes.KeyManagerTypeCustomer {
					continue // only customer-managed keys are actionable
				}
				rot, err := client.GetKeyRotationStatus(sc.Ctx, &kms.GetKeyRotationStatusInput{KeyId: &keyID})
				if err != nil {
					continue // rotation not applicable / not readable for this key
				}
				st.AddKMSKey(state.KMSKey{
					ID:              keyID,
					Region:          region,
					CustomerManaged: true,
					Enabled:         m.Enabled,
					RotationEnabled: rot.KeyRotationEnabled,
				})
			}
		}
	}
	return nil
}
