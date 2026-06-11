package gcp

import (
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(firewallCollector{}) }

type firewallCollector struct{}

func (firewallCollector) Name() string { return "gcp:firewall" }

// Collect gathers VPC firewall rules across the in-scope projects so the checks
// can flag ingress rules open to the internet.
func (firewallCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	svc, err := compute.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return err
	}
	for _, project := range sc.GCP.Projects {
		_ = svc.Firewalls.List(project).Pages(sc.Ctx, func(page *compute.FirewallList) error {
			for _, fw := range page.Items {
				r := state.FirewallRule{
					Name:         fw.Name,
					Project:      project,
					Network:      lastSegment(fw.Network),
					Direction:    fw.Direction,
					Disabled:     fw.Disabled,
					SourceRanges: fw.SourceRanges,
				}
				for _, a := range fw.Allowed {
					r.Allowed = append(r.Allowed, allowedSpec(a))
				}
				st.AddFirewallRule(r)
			}
			return nil
		})
	}
	return nil
}

// allowedSpec renders a firewall allow entry as "proto:port,port" or just the
// protocol ("all", "tcp") when no ports are listed.
func allowedSpec(a *compute.FirewallAllowed) string {
	if len(a.Ports) == 0 {
		return a.IPProtocol
	}
	return fmt.Sprintf("%s:%s", a.IPProtocol, strings.Join(a.Ports, ","))
}

// lastSegment returns the trailing path segment of a GCP self-link/URL.
func lastSegment(url string) string {
	if i := strings.LastIndex(url, "/"); i >= 0 {
		return url[i+1:]
	}
	return url
}
