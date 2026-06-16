package aws

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestMonitoringFlagsMissingControls(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("123456789012")
	// Root-usage (4.3) is covered: a matching filter whose metric has an alarm.
	st.AddLogMetricFilter(state.LogMetricFilter{
		Pattern:     `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS }`,
		MetricNames: []string{"RootUsage"}, Region: "us-east-1",
	})
	st.AddAlarmedMetric("RootUsage")
	// Unauthorized-calls (4.1) has a filter but NO alarm → not covered.
	st.AddLogMetricFilter(state.LogMetricFilter{
		Pattern:     `{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }`,
		MetricNames: []string{"UnauthorizedCalls"}, Region: "us-east-1",
	})

	fs, _ := cloudWatchMonitoring{}.Evaluate(nil, st)
	covered := map[string]bool{}
	for _, f := range fs {
		covered[f.Resource.Name] = true
	}
	// 4.3 is satisfied, so it must NOT be flagged.
	if covered["CIS 4.3"] {
		t.Error("root-usage (4.3) is filter+alarm covered and must not be flagged")
	}
	// 4.1 has a filter but no alarm → flagged.
	if !covered["CIS 4.1"] {
		t.Error("unauthorized-calls (4.1) has no alarm and must be flagged")
	}
	// Most of the remaining controls have no filter at all → flagged.
	if len(fs) < 10 {
		t.Fatalf("expected most monitoring controls flagged, got %d", len(fs))
	}
	for _, f := range fs {
		if !strings.Contains(f.Description, "CIS 4.") {
			t.Errorf("each finding should name its CIS control: %q", f.Description)
		}
	}
}

func TestMonitoringSkipsWhenNoDataCollected(t *testing.T) {
	st := state.New()
	st.SetAWSAccount("1")
	// No filters and no alarms collected (e.g. denied) → do not fabricate fails.
	if fs, _ := (cloudWatchMonitoring{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("no collected data should yield no findings, got %d", len(fs))
	}
}
