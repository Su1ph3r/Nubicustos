package azure

import (
	"fmt"
	"sort"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCheck(defenderPlanFree{}) }

// defenderPlanFree flags subscriptions where Microsoft Defender for Cloud plans
// are left on the Free tier, aggregating the free plans into one finding per
// subscription so the report is one actionable item per account rather than one
// per resource type.
type defenderPlanFree struct{}

func (defenderPlanFree) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_defender_plan_free", Title: "Microsoft Defender for Cloud plans on the Free tier",
		Provider: "azure", Service: "defender", Severity: findings.SeverityMedium,
		Rationale:   "Resource-type plans on the Free tier receive no Defender for Cloud advanced threat protection (vulnerability assessment, threat detection, JIT access), so attacks against those resources go undetected.",
		Impact:      "Threats against servers, storage, SQL, App Service, and other resource types are not detected or alerted.",
		Remediation: "Enable the Standard tier for the relevant plans: az security pricing create --name <plan> --tier Standard",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "2.1"}},
	}
}

func (c defenderPlanFree) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil || len(st.Azure.DefenderPlans) == 0 {
		return nil, nil
	}
	now := time.Now().UTC()

	freeBySub := map[string][]findings.Affected{}
	for _, p := range st.Azure.DefenderPlans {
		if p.Tier != "Free" {
			continue
		}
		freeBySub[p.Subscription] = append(freeBySub[p.Subscription], findings.Affected{
			Type: "defender_plan", ID: p.Name, Detail: p.Name + " is on the Free tier",
		})
	}

	subs := make([]string, 0, len(freeBySub))
	for s := range freeBySub {
		subs = append(subs, s)
	}
	sort.Strings(subs)

	var out []findings.Finding
	for _, sub := range subs {
		items := freeBySub[sub]
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		scope := findings.Resource{ID: sub, Name: sub, Type: "azure_subscription", Provider: "azure", Account: sub}
		desc := fmt.Sprintf("%d Defender for Cloud plan(s) are on the Free tier in subscription %s.", len(items), sub)
		out = append(out, findings.NewAggregate(c.Spec(), scope, desc, items, now))
	}
	return out, nil
}
