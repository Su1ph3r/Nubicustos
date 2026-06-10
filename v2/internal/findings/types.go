// Package findings defines the normalized domain model shared across the
// scan engine: checks, resources, findings, and the evidence/metadata they carry.
//
// These types are deliberately storage- and provider-agnostic. Collectors
// populate state, checks read state and emit Findings, and the store/export
// layers persist or serialize them. Every Finding is meant to be self-contained
// enough to render a complete report item (rationale, impact, remediation, PoC)
// without a second lookup.
package findings

import "time"

// Severity is the normalized severity scale, consistent across every source.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank returns a sortable weight (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Status tracks the lifecycle of a finding across scans.
type Status string

const (
	StatusOpen       Status = "open"
	StatusResolved   Status = "resolved"
	StatusSuppressed Status = "suppressed"
)

// Reachability annotates whether an "exposure" finding is actually reachable
// once the network model (SG + NACL + routes) is applied. Populated by the
// reachability solver (plan §9.5); defaults to Unknown until then.
type Reachability string

const (
	ReachUnknown Reachability = "unknown"
	ReachYes     Reachability = "reachable"
	ReachNo      Reachability = "not-reachable"
)

// Vantage records where an active-validation proof was obtained from (plan §9.1).
type Vantage string

const (
	VantageExternal      Vantage = "external"      // no credentials, operator network vantage
	VantageAuthenticated Vantage = "authenticated" // scan creds, exercised as a low-priv check
)

// ComplianceRef maps a check to a control in a compliance framework.
type ComplianceRef struct {
	Framework string `json:"framework"` // e.g. "CIS AWS 3.0"
	Control   string `json:"control"`   // e.g. "2.1.1"
}

// CheckSpec is the static, resource-independent metadata for a check. It is the
// single source of truth for how a finding is described and remediated; the
// PoC field is a template parameterized per-resource at finding time.
type CheckSpec struct {
	ID          string          `json:"id"`       // stable canonical id, e.g. "aws_s3_public_access"
	Title       string          `json:"title"`    // short headline
	Provider    string          `json:"provider"` // aws | azure | gcp | k8s
	Service     string          `json:"service"`  // s3 | iam | ec2 ...
	Severity    Severity        `json:"severity"`
	Rationale   string          `json:"rationale"`   // why it matters
	Impact      string          `json:"impact"`      // what an attacker gains
	Remediation string          `json:"remediation"` // exact CLI to fix
	PoC         string          `json:"poc"`         // verification command template
	Compliance  []ComplianceRef `json:"compliance,omitempty"`
	References  []string        `json:"references,omitempty"`
}

// Resource identifies the cloud object a finding is about.
type Resource struct {
	ID       string            `json:"id"`
	Name     string            `json:"name,omitempty"`
	Type     string            `json:"type"`
	Provider string            `json:"provider"`
	Account  string            `json:"account,omitempty"` // account / subscription / project
	Region   string            `json:"region,omitempty"`
	ARN      string            `json:"arn,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Affected is one item covered by an aggregate finding — a region, a security
// group rule, a snapshot ARN. Posture/control-level checks (e.g. "Config is not
// recording in these regions") emit a single finding whose Affected list
// enumerates everything in scope, instead of one finding per item.
type Affected struct {
	Type   string `json:"type,omitempty"` // region | sg_rule | vpc | ebs_snapshot | ami | rds_snapshot | arn
	ID     string `json:"id,omitempty"`   // resource id (e.g. sg-123, snap-abc)
	Region string `json:"region,omitempty"`
	ARN    string `json:"arn,omitempty"`
	Detail string `json:"detail,omitempty"` // free-form note (e.g. "exposes SSH (22)")
}

// Evidence captures the proof produced by the active-validation pass (plan §9.1).
type Evidence struct {
	Vantage    Vantage   `json:"vantage"`
	Request    string    `json:"request"`  // command / request issued
	Response   string    `json:"response"` // captured response (truncated, secret-safe)
	Verdict    string    `json:"verdict"`  // confirmed | unconfirmed | blocked
	CapturedAt time.Time `json:"captured_at"`
}

// Finding is a single normalized result, self-contained for reporting.
type Finding struct {
	ID          string          `json:"id"` // stable: checkID scoped to resource
	CheckID     string          `json:"check_id"`
	Title       string          `json:"title"`
	Severity    Severity        `json:"severity"`
	Status      Status          `json:"status"`
	Provider    string          `json:"provider"`
	Service     string          `json:"service"`
	Resource    Resource        `json:"resource"`
	Description string          `json:"description"`
	Rationale   string          `json:"rationale,omitempty"`
	Impact      string          `json:"impact,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	PoC         string          `json:"poc,omitempty"`
	Reachable   Reachability    `json:"reachable"`
	Compliance  []ComplianceRef `json:"compliance,omitempty"`
	References  []string        `json:"references,omitempty"`
	Affected    []Affected      `json:"affected,omitempty"`
	Evidence    []Evidence      `json:"evidence,omitempty"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
}

// New builds a Finding from a CheckSpec and the resource it concerns, copying
// the descriptive metadata so the finding stands alone. The caller supplies the
// rendered (resource-specific) PoC and description.
func New(spec CheckSpec, res Resource, description, poc string, seen time.Time) Finding {
	return Finding{
		ID:          spec.ID + "::" + res.ID,
		CheckID:     spec.ID,
		Title:       spec.Title,
		Severity:    spec.Severity,
		Status:      StatusOpen,
		Provider:    spec.Provider,
		Service:     spec.Service,
		Resource:    res,
		Description: description,
		Rationale:   spec.Rationale,
		Impact:      spec.Impact,
		Remediation: spec.Remediation,
		PoC:         poc,
		Reachable:   ReachUnknown,
		Compliance:  spec.Compliance,
		References:  spec.References,
		FirstSeen:   seen,
		LastSeen:    seen,
	}
}

// NewAggregate builds a single finding that covers many affected items. The
// scope resource is the shared owner of the items (typically the account); the
// items list enumerates every affected region/rule/resource. Use this for
// control-level checks where one finding-with-a-list reads better than many.
func NewAggregate(spec CheckSpec, scope Resource, description string, items []Affected, seen time.Time) Finding {
	f := New(spec, scope, description, spec.PoC, seen)
	f.Affected = items
	return f
}
