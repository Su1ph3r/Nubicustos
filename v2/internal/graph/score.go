package graph

import (
	"math"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// scorePath assembles a Path with a 0-100 risk score and a severity. The score
// is exploitability x impact (each 0..1) scaled to 100; severity is the more
// severe of the score band and an optional intrinsic floor (e.g. root compromise
// is Critical regardless of how the formula scores its exploitability).
func (b *builder) scorePath(id, title, rationale string, exploit, impact float64, floor findings.Severity, nodes []Node, edges []Edge) Path {
	score := clampScore(int(math.Round(exploit * impact * 100)))
	sev := severityForScore(score)
	if floor != "" && floor.Rank() > sev.Rank() {
		sev = floor
	}
	return Path{
		ID:        id,
		Title:     title,
		Score:     score,
		Severity:  sev,
		Rationale: rationale,
		Nodes:     nodes,
		Edges:     edges,
	}
}

// fixedPath builds a path with an explicit severity and score, for categorical
// risks (external/wildcard/OIDC trust) where severity is intrinsic rather than
// the product of an exploitability/impact estimate.
func fixedPath(id, title, rationale string, sev findings.Severity, score int, nodes []Node, edges []Edge) Path {
	return Path{
		ID:        id,
		Title:     title,
		Score:     clampScore(score),
		Severity:  sev,
		Rationale: rationale,
		Nodes:     nodes,
		Edges:     edges,
	}
}

// applyReachability annotates an internet-exposure path with a network
// reachability verdict and re-scores it: a target that is not actually reachable
// is downgraded (not dropped, per §9.5), and a confirmed-reachable one is noted.
//
// Precondition: pass only floorless exposure paths. The ReachNo branch re-derives
// severity from the scaled score alone; a path built with an intrinsic severity
// floor would lose that floor here. The only callers (the EC2 instance exposure
// paths) are built with no floor, so this holds.
func applyReachability(p Path, r findings.Reachability) Path {
	p.Reachable = r
	switch r {
	case findings.ReachNo:
		p.Score = clampScore(int(float64(p.Score) * 0.3))
		p.Severity = severityForScore(p.Score)
		p.Rationale = "Not reachable from the internet (no internet-gateway route or no permitting security group) — downgraded. " + p.Rationale
	case findings.ReachYes:
		p.Rationale = "Confirmed reachable from the internet. " + p.Rationale
	}
	return p
}

func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

// severityForScore maps the 0-100 risk score onto the shared severity scale.
func severityForScore(score int) findings.Severity {
	switch {
	case score >= 80:
		return findings.SeverityCritical
	case score >= 60:
		return findings.SeverityHigh
	case score >= 40:
		return findings.SeverityMedium
	case score >= 20:
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}
