package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&ec2Collector{}) }

type ec2Collector struct{}

func (ec2Collector) Name() string { return "aws:ec2" }

// Collect gathers EC2 posture across every scanned region: security-group
// ingress, instance public-IP/IMDSv2 posture, EBS volume encryption, and the
// account-level EBS default-encryption flag. Regional failures are tolerated so
// one denied/opted-out region does not blank the rest.
func (ec2Collector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		client := ec2.NewFromConfig(sc.AWS, func(o *ec2.Options) { o.Region = region })
		collectSecurityGroups(sc, client, region, st)
		collectInstances(sc, client, region, st)
		collectVolumes(sc, client, region, st)

		if def, err := client.GetEbsEncryptionByDefault(sc.Ctx, &ec2.GetEbsEncryptionByDefaultInput{}); err == nil {
			st.SetEBSDefaultEncryption(region, awssdk.ToBool(def.EbsEncryptionByDefault))
		}
	}
	return nil
}

func collectSecurityGroups(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	pager := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, g := range page.SecurityGroups {
			sg := state.SecurityGroup{
				ID:     awssdk.ToString(g.GroupId),
				Name:   awssdk.ToString(g.GroupName),
				Region: region,
			}
			for _, perm := range g.IpPermissions {
				sg.Ingress = append(sg.Ingress, ingressRule(perm))
			}
			st.AddSecurityGroup(sg)
		}
	}
}

// ingressRule normalizes an IpPermission, flagging open-to-world CIDRs.
func ingressRule(perm ec2types.IpPermission) state.IngressRule {
	r := state.IngressRule{
		Protocol: awssdk.ToString(perm.IpProtocol),
		FromPort: int(awssdk.ToInt32(perm.FromPort)),
		ToPort:   int(awssdk.ToInt32(perm.ToPort)),
	}
	for _, ipr := range perm.IpRanges {
		if awssdk.ToString(ipr.CidrIp) == "0.0.0.0/0" {
			r.OpenV4 = true
		}
	}
	for _, ipr := range perm.Ipv6Ranges {
		if awssdk.ToString(ipr.CidrIpv6) == "::/0" {
			r.OpenV6 = true
		}
	}
	return r
}

func collectInstances(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	pager := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, r := range page.Reservations {
			for _, inst := range r.Instances {
				ec2i := state.EC2Instance{
					ID:       awssdk.ToString(inst.InstanceId),
					Region:   region,
					PublicIP: awssdk.ToString(inst.PublicIpAddress),
				}
				if inst.MetadataOptions != nil {
					ec2i.IMDSv2Required = inst.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired
				}
				st.AddInstance(ec2i)
			}
		}
	}
}

func collectVolumes(sc *engine.ScanContext, client *ec2.Client, region string, st *state.State) {
	pager := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, v := range page.Volumes {
			st.AddVolume(state.EBSVolume{
				ID:        awssdk.ToString(v.VolumeId),
				Region:    region,
				Encrypted: awssdk.ToBool(v.Encrypted),
			})
		}
	}
}
