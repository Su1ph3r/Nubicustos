package aws

import (
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&acmCollector{}) }

type acmCollector struct{}

func (acmCollector) Name() string { return "aws:acm" }

// Collect lists ACM certificates per region and resolves each one's status and
// expiry so the checks can flag expired or soon-to-expire certificates.
func (acmCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := acm.NewFromConfig(sc.AWS, func(o *acm.Options) { o.Region = region })
		pager := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(sc.Ctx)
			if err != nil {
				break
			}
			for _, summary := range page.CertificateSummaryList {
				arn := awssdk.ToString(summary.CertificateArn)
				detail, err := client.DescribeCertificate(sc.Ctx, &acm.DescribeCertificateInput{CertificateArn: &arn})
				if err != nil || detail.Certificate == nil {
					continue
				}
				st.AddCertificate(certificateState(detail.Certificate, region))
			}
		}
	}
	return nil
}

func certificateState(c *acmtypes.CertificateDetail, region string) state.Certificate {
	cert := state.Certificate{
		ARN:        awssdk.ToString(c.CertificateArn),
		Region:     region,
		DomainName: awssdk.ToString(c.DomainName),
		Status:     string(c.Status),
	}
	if c.NotAfter != nil {
		cert.NotAfter = *c.NotAfter
		cert.DaysToExpiry = int(time.Until(*c.NotAfter).Hours() / 24)
	}
	cert.Expired = c.Status == acmtypes.CertificateStatusExpired ||
		(c.NotAfter != nil && c.NotAfter.Before(time.Now()))
	return cert
}
