package preflight

// Estate preflight extends the single-identity check to a whole cloud estate
// (plan §9.4): an AWS organization's member accounts, an Azure tenant's
// subscriptions, a GCP org's projects, or a kubeconfig's contexts. The command
// layer enumerates the estate and runs Evaluate per member (each against that
// member's own session); this file holds the provider-agnostic result shape and
// the worst-case rollup, so the aggregation is testable without live sessions.

// AccountReport pairs one estate member (account / subscription / project /
// context) with its preflight result.
type AccountReport struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Management bool   `json:"management,omitempty"` // AWS: the base/management account
	Report     Report `json:"report"`
}

// SkippedAccount records an estate member deliberately not checked (suspended,
// excluded, or an assume-role/access failure), with the reason — so a partial
// run never reads as full coverage.
type SkippedAccount struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}

// EstateReport is the multi-member preflight result. Base, when set, is the
// enumeration-access check on the identity discovery ran from (e.g. an AWS
// management account proving organizations:* + sts:AssumeRole); it is nil for
// providers whose single credential already spans the estate (Azure/GCP/K8s).
type EstateReport struct {
	Provider string           `json:"provider"`
	Scope    string           `json:"scope"` // human label, e.g. "organization", "subscriptions"
	Base     *Report          `json:"base,omitempty"`
	Accounts []AccountReport  `json:"accounts"`
	Skipped  []SkippedAccount `json:"skipped,omitempty"`
	Overall  Readiness        `json:"overall"`
}

// EstateOverall rolls the base enumeration check and every per-member verdict
// into one worst-case readiness. An estate where nothing at all could be checked
// (no base, no members) is Unknown — never Ready, which would falsely certify an
// unverified estate.
func EstateOverall(base *Report, accounts []AccountReport) Readiness {
	var rs []Readiness
	if base != nil {
		rs = append(rs, base.Overall)
	}
	for _, a := range accounts {
		rs = append(rs, a.Report.Overall)
	}
	if len(rs) == 0 {
		return ReadinessUnknown
	}
	return worstReadiness(rs...)
}
