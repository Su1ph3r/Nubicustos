package gcp

import (
	"errors"
	"fmt"
	"strings"

	logging "google.golang.org/api/logging/v2"
	monitoring "google.golang.org/api/monitoring/v3"
	"google.golang.org/api/option"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(monitoringCollector{}) }

type monitoringCollector struct{}

func (monitoringCollector) Name() string { return "gcp:monitoring" }

// Collect gathers each project's log-based metrics and the metric names
// referenced by alert policies (CIS GCP section 2), so the check can verify a
// metric + alert exists for sensitive changes. A read failure leaves ReadOK
// false so the check judges only what was collected.
func (monitoringCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "gcp" || sc.GCP.Credentials == nil {
		return nil
	}
	logSvc, err := logging.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp monitoring: building logging client: %w", err)
	}
	monSvc, err := monitoring.NewService(sc.Ctx, option.WithCredentials(sc.GCP.Credentials))
	if err != nil {
		return fmt.Errorf("gcp monitoring: building monitoring client: %w", err)
	}
	var errs []error
	for _, project := range sc.GCP.Projects {
		m := state.GCPMonitoring{Project: project}
		metrics, mErr := listLogMetrics(sc, logSvc, project)
		alerted, aErr := listAlertedMetrics(sc, monSvc, project)
		if mErr != nil {
			errs = append(errs, mErr)
		}
		if aErr != nil {
			errs = append(errs, aErr)
		}
		if mErr == nil && aErr == nil {
			m.ReadOK = true
			m.Metrics = metrics
			m.AlertedMetricNames = alerted
		}
		st.AddGCPMonitoring(m)
	}
	return errors.Join(errs...)
}

func listLogMetrics(sc *engine.ScanContext, svc *logging.Service, project string) ([]state.GCPLogMetric, error) {
	var out []state.GCPLogMetric
	err := svc.Projects.Metrics.List("projects/"+project).Pages(sc.Ctx, func(page *logging.ListLogMetricsResponse) error {
		for _, m := range page.Metrics {
			out = append(out, state.GCPLogMetric{Name: m.Name, Filter: m.Filter})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("gcp monitoring: listing log metrics in %s: %w", project, err)
	}
	return out, nil
}

func listAlertedMetrics(sc *engine.ScanContext, svc *monitoring.Service, project string) ([]string, error) {
	var out []string
	err := svc.Projects.AlertPolicies.List("projects/"+project).Pages(sc.Ctx, func(page *monitoring.ListAlertPoliciesResponse) error {
		for _, pol := range page.AlertPolicies {
			for _, cond := range pol.Conditions {
				if cond.ConditionThreshold == nil {
					continue
				}
				if name := userMetricFromFilter(cond.ConditionThreshold.Filter); name != "" {
					out = append(out, name)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("gcp monitoring: listing alert policies in %s: %w", project, err)
	}
	return out, nil
}

// userMetricFromFilter extracts the user log-metric name from an alert-policy
// threshold filter of the form metric.type="logging.googleapis.com/user/<name>".
func userMetricFromFilter(filter string) string {
	const marker = "logging.googleapis.com/user/"
	i := strings.Index(filter, marker)
	if i < 0 {
		return ""
	}
	rest := filter[i+len(marker):]
	// The name ends at the closing quote (or any non-name character).
	end := strings.IndexAny(rest, "\"' ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
