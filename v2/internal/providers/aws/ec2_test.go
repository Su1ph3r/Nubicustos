package aws

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestIngressRuleCapturesSources(t *testing.T) {
	perm := ec2types.IpPermission{
		IpProtocol: awssdk.String("tcp"),
		FromPort:   awssdk.Int32(443),
		ToPort:     awssdk.Int32(443),
		IpRanges: []ec2types.IpRange{
			{CidrIp: awssdk.String("0.0.0.0/0")},
			{CidrIp: awssdk.String("10.1.0.0/16")},
		},
		Ipv6Ranges:       []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}},
		UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: awssdk.String("sg-source")}},
	}
	r := ingressRule(perm, nil)

	if !r.OpenV4 || !r.OpenV6 {
		t.Errorf("world-open shortcuts should be derived: v4=%v v6=%v", r.OpenV4, r.OpenV6)
	}
	if len(r.IPv4CIDRs) != 2 || r.IPv4CIDRs[1] != "10.1.0.0/16" {
		t.Errorf("IPv4 CIDRs = %v, want [0.0.0.0/0 10.1.0.0/16]", r.IPv4CIDRs)
	}
	if len(r.IPv6CIDRs) != 1 || r.IPv6CIDRs[0] != "::/0" {
		t.Errorf("IPv6 CIDRs = %v", r.IPv6CIDRs)
	}
	if len(r.SourceSGs) != 1 || r.SourceSGs[0] != "sg-source" {
		t.Errorf("source SGs = %v, want [sg-source]", r.SourceSGs)
	}
}

func TestIngressRuleNonWorldOpen(t *testing.T) {
	perm := ec2types.IpPermission{
		IpProtocol: awssdk.String("tcp"),
		FromPort:   awssdk.Int32(5432),
		ToPort:     awssdk.Int32(5432),
		IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("10.0.0.0/8")}},
	}
	r := ingressRule(perm, nil)
	if r.OpenV4 || r.OpenV6 {
		t.Errorf("a private CIDR must not set world-open: %+v", r)
	}
	if len(r.IPv4CIDRs) != 1 || r.IPv4CIDRs[0] != "10.0.0.0/8" {
		t.Errorf("IPv4 CIDRs = %v", r.IPv4CIDRs)
	}
}

func TestIngressRuleExpandsPrefixList(t *testing.T) {
	perm := ec2types.IpPermission{
		IpProtocol:    awssdk.String("tcp"),
		FromPort:      awssdk.Int32(443),
		ToPort:        awssdk.Int32(443),
		PrefixListIds: []ec2types.PrefixListId{{PrefixListId: awssdk.String("pl-123")}},
	}
	plCIDRs := map[string][]string{"pl-123": {"10.1.0.0/16", "2600:1f00::/40"}}
	r := ingressRule(perm, plCIDRs)

	if len(r.SourcePrefixLists) != 1 || r.SourcePrefixLists[0] != "pl-123" {
		t.Errorf("source prefix lists = %v, want [pl-123]", r.SourcePrefixLists)
	}
	if len(r.IPv4CIDRs) != 1 || r.IPv4CIDRs[0] != "10.1.0.0/16" {
		t.Errorf("prefix list IPv4 CIDR not expanded: %v", r.IPv4CIDRs)
	}
	if len(r.IPv6CIDRs) != 1 || r.IPv6CIDRs[0] != "2600:1f00::/40" {
		t.Errorf("prefix list IPv6 CIDR not expanded: %v", r.IPv6CIDRs)
	}
}
