// Package chain synthesizes the flagship runtime-proven attack chain by joining
// three signals the engine already gathers but never correlates:
//
//   - a control-plane secret — an AWS key recovered from a Lambda env var, EC2
//     userdata, or an SSM parameter (internal/secrets);
//   - proof the key is LIVE — an sts:GetCallerIdentity whoami that returns the
//     identity it maps to (internal/validate, under --capture-secrets --validate);
//   - the IAM privilege graph — whether that identity holds admin or can escalate
//     to it (internal/trust).
//
// The output is a single finding and attack path that no stateless, single-signal
// scanner can produce. Scout/Prowler/CloudSploit flag "a secret is in this Lambda
// env" and "this user is over-privileged" as two unrelated facts and never test
// the key or connect the two. This says: "the key in function ingest is LIVE,
// maps to user/deploy, and deploy can escalate to admin via iam:PutUserPolicy" —
// a runtime-proven, end-to-end compromise path.
//
// Synthesize is pure: it reads collected state and probed liveness and returns
// findings + graph paths. It runs only after the validation pass has proven
// liveness, so it is spliced into the graph post-build via graph.MergePaths.
package chain

import (
	"fmt"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
	"github.com/Su1ph3r/nubicustos/internal/trust"
)

// CheckID is the stable id of the synthesized attack-chain finding.
const CheckID = "aws_exposed_key_privesc_chain"

// LiveKey is a captured AWS key that an sts:GetCallerIdentity whoami proved live,
// paired with the identity it resolved to. Only live keys are passed to
// Synthesize; rejected/blocked keys carry no exploitable chain.
type LiveKey struct {
	Cred    secrets.AWSKeyCredential
	ARN     string // identity the key maps to, e.g. arn:aws:iam::123:user/deploy
	Account string
}

// Synthesize joins proven-live captured keys to the IAM privilege graph. For
// each live key whose identity holds administrative access or a privilege-
// escalation path, it emits one finding and one scored attack path. Keys whose
// identity holds no elevated privilege produce nothing here — the standalone
// exposed-secret finding already covers "a live key leaked"; the differentiator
// is the proven route from that key to account compromise.
//
// It is safe on nil/empty input and never panics on a malformed ARN (such a key
// is skipped). now stamps the emitted findings.
func Synthesize(a *state.AWS, live []LiveKey, now time.Time) ([]findings.Finding, []graph.Path) {
	if a == nil || len(live) == 0 {
		return nil, nil
	}
	rep := trust.Analyze(a)
	privByPrincipal := make(map[string]trust.Privilege, len(rep.Privs))
	for _, p := range rep.Privs {
		privByPrincipal[p.Kind+"/"+p.Name] = p
	}

	var fs []findings.Finding
	var paths []graph.Path
	for _, lk := range live {
		kind, name := parsePrincipalARN(lk.ARN)
		if kind == "" || name == "" {
			continue // unparseable identity — fail closed, synthesize nothing
		}
		p, ok := privByPrincipal[kind+"/"+name]
		if !ok {
			continue // live key, but its identity holds no admin/privesc to chain to
		}
		f, path := build(lk, kind, name, p, now)
		fs = append(fs, f)
		paths = append(paths, path)
	}
	return fs, paths
}

// build assembles the finding and graph path for one live-key→privileged-identity
// correlation.
func build(lk LiveKey, kind, name string, p trust.Privilege, now time.Time) (findings.Finding, graph.Path) {
	escalation, poc := escalationNarrative(kind, name, p)
	surface := surfaceLabel(lk.Cred.Surface)

	desc := fmt.Sprintf(
		"A live AWS key (%s) recovered from %s %q maps to %s %q, which %s. The key was confirmed live with sts:GetCallerIdentity, so this is an exploitable path from an exposed credential to account compromise — not a hypothetical one.",
		lk.Cred.Masked(), surface, lk.Cred.Resource, kind, name, escalation)

	res := findings.Resource{
		ID:       lk.Cred.Surface + ":" + lk.Cred.Resource,
		Name:     lk.Cred.Resource,
		Type:     "aws_" + lk.Cred.Surface,
		Provider: "aws",
		Account:  lk.Account,
		Region:   lk.Cred.Region,
	}

	ev := findings.Evidence{
		Vantage:    findings.VantageAuthenticated,
		Request:    fmt.Sprintf("sts:GetCallerIdentity(captured key %s from %s %q)", lk.Cred.Masked(), surface, lk.Cred.Resource),
		Response:   fmt.Sprintf("%s: LIVE → %s; identity %s %q %s", lk.Cred.Masked(), lk.ARN, kind, name, escalation),
		Verdict:    "confirmed",
		CapturedAt: now,
	}

	f := findings.Finding{
		ID:          CheckID + "::" + res.ID,
		CheckID:     CheckID,
		Title:       "Exposed AWS key is live and escalates to account compromise",
		Severity:    findings.SeverityCritical,
		Status:      findings.StatusOpen,
		Provider:    "aws",
		Service:     "iam",
		Resource:    res,
		Description: desc,
		Rationale:   "A credential leaked on the control plane is only theoretical until it is shown to be valid and the identity behind it is shown to be dangerous. Joining liveness with the privilege graph collapses that uncertainty into a confirmed, end-to-end compromise path.",
		Impact:      "An attacker who reads this credential can authenticate as the identity and escalate to full account control.",
		Remediation: fmt.Sprintf("Rotate/revoke the leaked key immediately, remove the secret from %s %q (use a secrets manager or the execution role instead), and apply least privilege to %s %q so a leaked credential cannot escalate.", surface, lk.Cred.Resource, kind, name),
		PoC:         poc,
		Reachable:   findings.ReachUnknown,
		Evidence:    []findings.Evidence{ev},
		FirstSeen:   now,
		LastSeen:    now,
	}

	path := buildPath(lk, kind, name, p, surface, escalation, poc)
	return f, path
}

// buildPath renders the three-hop graph path: exposed surface → live credential →
// privileged identity. The identity node id matches the one the graph builder
// assigns to that principal, so the chain's terminal node coincides with the
// trust dimension's holds-admin / can-escalate node rather than duplicating it.
func buildPath(lk LiveKey, kind, name string, p trust.Privilege, surface, escalation, poc string) graph.Path {
	surfaceNode := graph.Node{
		ID:     graph.ResourceNodeID("aws_"+lk.Cred.Surface, lk.Cred.Resource),
		Kind:   graph.NodeResource,
		Label:  surface + " " + lk.Cred.Resource,
		Type:   "aws_" + lk.Cred.Surface,
		Region: lk.Cred.Region,
	}
	keyNode := graph.Node{
		ID:    "credential:" + lk.Cred.Surface + ":" + lk.Cred.Resource + ":" + lk.Cred.Masked(),
		Kind:  graph.NodeResource,
		Label: "AWS key " + lk.Cred.Masked(),
		Type:  "aws_access_key",
	}
	principalNode := graph.Node{
		ID:    graph.PrincipalNodeID(kind + "/" + name),
		Kind:  graph.NodePrincipal,
		Label: name,
		Type:  "aws_iam_" + kind,
		ARN:   lk.ARN,
	}

	exposeEdge := graph.Edge{
		Src: surfaceNode.ID, Dst: keyNode.ID, Kind: graph.EdgeExposedSecret,
		Detail: fmt.Sprintf("AWS key %s is exposed in %s %q", lk.Cred.Masked(), surface, lk.Cred.Resource),
		PoC:    fmt.Sprintf("# read the %s of %q to recover the key material", surface, lk.Cred.Resource),
	}
	liveEdge := graph.Edge{
		Src: keyNode.ID, Dst: principalNode.ID, Kind: graph.EdgeLiveCredential,
		Detail: fmt.Sprintf("key is LIVE (sts:GetCallerIdentity) and maps to %s", lk.ARN),
		PoC:    fmt.Sprintf("AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=… aws sts get-caller-identity", lk.Cred.Masked()),
	}

	escalateKind := graph.EdgeCanEscalate
	score := 90
	if p.Admin {
		escalateKind = graph.EdgeHoldsAdmin
		score = 95
	}
	escalateEdge := graph.Edge{
		Src: principalNode.ID, Dst: principalNode.ID, Kind: escalateKind,
		Detail: fmt.Sprintf("%s %s %s", kind, name, escalation),
		PoC:    poc,
	}

	return graph.Path{
		ID:    "exposed-key-privesc:" + lk.Cred.Surface + ":" + lk.Cred.Resource + ":" + kind + "/" + name,
		Title: fmt.Sprintf("Exposed live key in %s %q escalates via %s %s", surface, lk.Cred.Resource, kind, name),
		Score: score,
		Severity:  findings.SeverityCritical,
		Reachable: findings.ReachYes,
		Rationale: "Confirmed end-to-end: a key leaked on the control plane is live, maps to a real identity, and that identity can reach administrative control.",
		Nodes:     []graph.Node{surfaceNode, keyNode, principalNode},
		Edges:     []graph.Edge{exposeEdge, liveEdge, escalateEdge},
	}
}

// escalationNarrative describes how the identity reaches admin and returns a
// concrete PoC for the escalation hop.
func escalationNarrative(kind, name string, p trust.Privilege) (narrative, poc string) {
	if p.Admin {
		return "holds administrator-equivalent permissions",
			fmt.Sprintf("# %s %s already holds admin — the live key grants full account control directly", kind, name)
	}
	actions := strings.Join(p.Privesc, ", ")
	return fmt.Sprintf("can escalate to administrator via %s (granted on Resource \"*\")", actions),
		fmt.Sprintf("# as %s %s, e.g. attach AdministratorAccess to self via %s", kind, name, firstAction(p.Privesc))
}

func firstAction(actions []string) string {
	if len(actions) == 0 {
		return "the granted privilege-escalation action"
	}
	return actions[0]
}

// surfaceLabel maps the secrets collector's surface tag to a readable phrase.
func surfaceLabel(surface string) string {
	switch surface {
	case "lambda_env":
		return "Lambda environment variable in function"
	case "ec2_userdata":
		return "EC2 userdata of instance"
	case "ssm_parameter":
		return "SSM parameter"
	default:
		return surface
	}
}

// parsePrincipalARN extracts the IAM principal kind and name an STS caller
// identity resolves to. It handles the long-term user/role forms and the
// assumed-role form returned for temporary (ASIA) credentials:
//
//	arn:aws:iam::123:user/deploy                      -> ("user", "deploy")
//	arn:aws:iam::123:role/Builder                     -> ("role", "Builder")
//	arn:aws:sts::123:assumed-role/Builder/i-0abc      -> ("role", "Builder")
//
// A path prefix on a user (e.g. user/team/deploy) resolves to the trailing
// name segment, matching how the IAM collector records principal names.
// Unrecognized forms return ("", "") so the caller fails closed.
func parsePrincipalARN(arn string) (kind, name string) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return "", ""
	}
	resource := parts[5] // e.g. "user/deploy" or "assumed-role/Builder/session"
	seg := strings.SplitN(resource, "/", 2)
	if len(seg) != 2 || seg[1] == "" {
		return "", ""
	}
	switch seg[0] {
	case "user":
		return "user", lastSegment(seg[1])
	case "role":
		return "role", lastSegment(seg[1])
	case "assumed-role":
		// assumed-role/<RoleName>/<sessionName> — the role name is the first segment.
		role := strings.SplitN(seg[1], "/", 2)[0]
		if role == "" {
			return "", ""
		}
		return "role", role
	default:
		return "", ""
	}
}

// lastSegment returns the final "/"-delimited element (strips an IAM path prefix).
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
