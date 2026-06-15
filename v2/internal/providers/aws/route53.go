package aws

import (
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&route53Collector{}) }

type route53Collector struct{}

func (route53Collector) Name() string { return "aws:route53" }

// Collect walks every public hosted zone and records the CNAME and alias
// A/AAAA records along with the target each delegates to. Plain A/AAAA records
// pointing at literal IPs are skipped — only records that delegate to another
// hostname can be left dangling when their target is deprovisioned, which is the
// subdomain-takeover surface the dangling-DNS check evaluates.
//
// Route 53 is a global service, so this runs once per scan (not per region).
func (route53Collector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	client := route53.NewFromConfig(sc.AWS)

	zones := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
	for zones.HasMorePages() {
		page, err := zones.NextPage(sc.Ctx)
		if err != nil {
			return err
		}
		for _, z := range page.HostedZones {
			// Private zones never resolve from the internet, so they are not a
			// public subdomain-takeover surface.
			if z.Config != nil && z.Config.PrivateZone {
				continue
			}
			if err := collectZoneRecords(sc, client, z, st); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectZoneRecords pages through one zone's record sets (ListResourceRecordSets
// has no SDK paginator, so we follow NextRecordName/Type manually).
func collectZoneRecords(sc *engine.ScanContext, client *route53.Client, z r53types.HostedZone, st *state.State) error {
	zoneID := awssdk.ToString(z.Id)
	zoneName := awssdk.ToString(z.Name)

	in := &route53.ListResourceRecordSetsInput{HostedZoneId: z.Id}
	for {
		out, err := client.ListResourceRecordSets(sc.Ctx, in)
		if err != nil {
			return err
		}
		for _, rr := range out.ResourceRecordSets {
			if rec, ok := takeoverCandidate(rr, zoneID, zoneName); ok {
				st.AddRoute53Record(rec)
			}
		}
		if !out.IsTruncated {
			break
		}
		in.StartRecordName = out.NextRecordName
		in.StartRecordType = out.NextRecordType
		in.StartRecordIdentifier = out.NextRecordIdentifier
	}
	return nil
}

// takeoverCandidate extracts a delegating record (CNAME or alias A/AAAA) and its
// target. It returns ok=false for anything that cannot dangle onto a third-party
// target: plain IP records, and the apex NS/SOA bookkeeping records.
func takeoverCandidate(rr r53types.ResourceRecordSet, zoneID, zoneName string) (state.Route53Record, bool) {
	name := awssdk.ToString(rr.Name)
	rtype := string(rr.Type)

	// Alias A/AAAA records carry their target in AliasTarget.DNSName rather than
	// ResourceRecords; these alias an AWS service endpoint that can be torn down.
	if rr.AliasTarget != nil {
		if rtype != string(r53types.RRTypeA) && rtype != string(r53types.RRTypeAaaa) {
			return state.Route53Record{}, false
		}
		target := normalizeTarget(awssdk.ToString(rr.AliasTarget.DNSName))
		if target == "" {
			return state.Route53Record{}, false
		}
		return state.Route53Record{
			ZoneID: zoneID, Zone: zoneName, Name: name,
			Type: rtype, Target: target, Alias: true,
		}, true
	}

	// Plain CNAME — the classic dangling-DNS shape.
	if rtype == string(r53types.RRTypeCname) {
		for _, v := range rr.ResourceRecords {
			target := normalizeTarget(awssdk.ToString(v.Value))
			if target != "" {
				// A CNAME has exactly one value, but guard the slice regardless.
				return state.Route53Record{
					ZoneID: zoneID, Zone: zoneName, Name: name,
					Type: rtype, Target: target, Alias: false,
				}, true
			}
		}
	}
	return state.Route53Record{}, false
}

// normalizeTarget lower-cases a DNS target and strips the trailing dot so it can
// be compared against fingerprint suffixes and dialed for resolution.
func normalizeTarget(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
