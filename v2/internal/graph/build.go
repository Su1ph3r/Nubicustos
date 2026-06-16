package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/reachability"
	"github.com/Su1ph3r/nubicustos/internal/state"
	"github.com/Su1ph3r/nubicustos/internal/trust"
)

// Build constructs the attack-path graph from collected state. It is safe to
// call on empty or non-AWS state (it returns an empty graph). The graph always
// contains the singleton internet node.
//
// rch, when non-nil, annotates and re-scores internet-exposure paths with
// network reachability (§9.5) so "open on paper but unreachable" resources are
// downgraded rather than presented as live exposure. Pass nil to skip that.
func Build(st *state.State, rch *reachability.Result) *Graph {
	b := &builder{nodes: map[string]Node{}, rch: rch}
	b.addNode(Node{ID: InternetNodeID, Kind: NodeInternet, Label: "Internet"})

	if st != nil && st.AWS != nil {
		b.fromAWS(st.AWS)
	}

	sort.SliceStable(b.g.Paths, func(i, j int) bool {
		return b.g.Paths[i].Score > b.g.Paths[j].Score
	})
	return b.g
}

type builder struct {
	g     *Graph
	nodes map[string]Node      // id -> node, for O(1) dedup and lookup
	rch   *reachability.Result // network reachability, optional
}

func (b *builder) init() {
	if b.g == nil {
		b.g = &Graph{}
	}
	if b.nodes == nil {
		b.nodes = map[string]Node{}
	}
}

// addNode adds a node once (deduped by ID).
func (b *builder) addNode(n Node) {
	b.init()
	if _, ok := b.nodes[n.ID]; ok {
		return
	}
	b.nodes[n.ID] = n
	b.g.Nodes = append(b.g.Nodes, n)
}

func (b *builder) addEdge(e Edge) {
	b.init()
	b.g.Edges = append(b.g.Edges, e)
}

func (b *builder) addPath(p Path) {
	b.init()
	b.g.Paths = append(b.g.Paths, p)
}

// ResourceNodeID and PrincipalNodeID build the canonical, kind-scoped node ids.
// They are exported so post-scan synthesis (e.g. the attack-chain join) can
// address the very same principal/resource nodes the builder created, letting a
// synthesized path's terminal node coincide with the trust dimension's
// holds-admin / can-escalate node rather than duplicating it.
func ResourceNodeID(rtype, id string) string { return "resource:" + rtype + ":" + id }
func PrincipalNodeID(id string) string       { return "principal:" + id }

func resourceNodeID(rtype, id string) string { return ResourceNodeID(rtype, id) }
func principalNodeID(id string) string       { return PrincipalNodeID(id) }

func (b *builder) fromAWS(a *state.AWS) {
	b.exposedInstances(a)
	b.exposedSecurityGroups(a)
	b.exposedRDS(a)
	b.exposedLoadBalancers(a)
	b.exposedS3(a)
	b.exposedSharedArtifacts(a)
	b.lateralReachability(a)
	b.rootPrincipal(a)
	b.trustEdges(a)
}

// lateralReachability renders the indirect-exposure paths the reachability solver
// discovers: a resource that is not itself internet-facing but is reachable from
// one that is. Two forms, both invisible to a per-resource scan:
//   - a security group that admits a world-open source group (exposure chains
//     inward one hop): internet -> world-open group -> this group;
//   - a security group in a private VPC that admits a CIDR overlapping an
//     internet-exposed peer VPC across an active peering: internet -> peer VPC ->
//     this group.
func (b *builder) lateralReachability(a *state.AWS) {
	for _, t := range reachability.TransitiveWorldOpenSGs(a) {
		srcNode := Node{ID: resourceNodeID("aws_security_group", t.SourceSG), Kind: NodeResource, Label: t.SourceName, Type: "aws_security_group", Region: t.Region}
		dstNode := Node{ID: resourceNodeID("aws_security_group", t.SecurityGroup), Kind: NodeResource, Label: t.SGName, Type: "aws_security_group", Region: t.Region}
		b.addNode(srcNode)
		b.addNode(dstNode)
		exposeEdge := Edge{
			Src: InternetNodeID, Dst: srcNode.ID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("security group %s is open to the internet", t.SourceName),
			PoC:    fmt.Sprintf("# %s admits 0.0.0.0/0; reach a host in it from the internet", t.SourceSG),
		}
		lateralEdge := Edge{
			Src: srcNode.ID, Dst: dstNode.ID, Kind: EdgeLateralReachable,
			Detail: fmt.Sprintf("group %s admits source group %s on %s", t.SGName, t.SourceName, t.Ports),
			PoC:    fmt.Sprintf("# from a host in %s, connect to hosts in %s on %s", t.SourceSG, t.SecurityGroup, t.Ports),
		}
		b.addEdge(exposeEdge)
		b.addEdge(lateralEdge)
		b.addPath(b.scorePath(
			"lateral-sg:"+t.SourceSG+":"+t.SecurityGroup,
			fmt.Sprintf("Security group %s is reachable from the internet via world-open group %s", t.SGName, t.SourceName),
			"The group has no world-open rule of its own, but it admits a group that does, so internet exposure chains inward one hop.",
			0.5, 0.5, "",
			[]Node{b.node(InternetNodeID), srcNode, dstNode},
			[]Edge{exposeEdge, lateralEdge},
		))
	}

	for _, e := range reachability.SGPeerReachable(a) {
		peerNode := Node{ID: resourceNodeID("aws_vpc", e.InternetVPC), Kind: NodeResource, Label: e.InternetVPC, Type: "aws_vpc", Region: e.Region}
		dstNode := Node{ID: resourceNodeID("aws_security_group", e.SecurityGroup), Kind: NodeResource, Label: e.SGName, Type: "aws_security_group", Region: e.Region}
		b.addNode(peerNode)
		b.addNode(dstNode)
		exposeEdge := Edge{
			Src: InternetNodeID, Dst: peerNode.ID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("VPC %s reaches the internet (peered with the private VPC over %s)", e.InternetVPC, e.PeeringID),
			PoC:    fmt.Sprintf("# gain a foothold in internet-exposed VPC %s", e.InternetVPC),
		}
		lateralEdge := Edge{
			Src: peerNode.ID, Dst: dstNode.ID, Kind: EdgeLateralReachable,
			Detail: fmt.Sprintf("group %s admits %s (overlaps peer range %s) on %s across peering %s", e.SGName, e.MatchedCIDR, e.PeerCIDR, e.Ports, e.PeeringID),
			PoC:    fmt.Sprintf("# from a host in %s, connect to %s on %s over the peering", e.InternetVPC, e.SecurityGroup, e.Ports),
		}
		b.addEdge(exposeEdge)
		b.addEdge(lateralEdge)
		b.addPath(b.scorePath(
			"lateral-peer-sg:"+e.PeeringID+":"+e.SecurityGroup,
			fmt.Sprintf("Security group %s is reachable across peering from internet-exposed VPC %s", e.SGName, e.InternetVPC),
			"The group admits a private CIDR that is the range of an internet-facing peer VPC, so a foothold there reaches it across the peering despite no world-open rule.",
			0.5, 0.6, "",
			[]Node{b.node(InternetNodeID), peerNode, dstNode},
			[]Edge{exposeEdge, lateralEdge},
		))
	}
}

// exposedInstances: an instance with a public IP is internet-addressable. If it
// also allows IMDSv1, that is the classic SSRF -> instance-role-credential path
// (a genuine 2-hop chain), independent of which role is attached (role identity
// arrives with the trust collector, plan §9.3).
func (b *builder) exposedInstances(a *state.AWS) {
	for _, inst := range a.Instances {
		if inst.PublicIP == "" {
			continue
		}
		nodeID := resourceNodeID("aws_ec2_instance", inst.ID)
		b.addNode(Node{ID: nodeID, Kind: NodeResource, Label: inst.ID, Type: "aws_ec2_instance", Region: inst.Region})

		exposeEdge := Edge{
			Src: InternetNodeID, Dst: nodeID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("instance %s has public IP %s", inst.ID, inst.PublicIP),
			PoC:    fmt.Sprintf("nmap -Pn -sS %s   # enumerate internet-reachable services", inst.PublicIP),
		}
		b.addEdge(exposeEdge)

		reach := b.instanceReach(inst)

		if inst.IMDSv2Required {
			// Exposure alone is a single-hop path of modest severity.
			p := b.scorePath(
				"internet-exposed-instance:"+inst.ID,
				fmt.Sprintf("Internet-exposed EC2 instance %s", inst.ID),
				"Instance is directly addressable from the internet via its public IP; any exposed service is reachable without a prior foothold.",
				0.6, 0.5, "",
				[]Node{b.node(InternetNodeID), b.node(nodeID)},
				[]Edge{exposeEdge},
			)
			b.addPath(applyReachability(p, reach))
			continue
		}

		// IMDSv1 reachable: model the metadata-credential hop. Name the role when
		// the instance-profile binding resolved it; otherwise label it generically.
		credLabel := "instance role credentials"
		roleNote := "The role's exact permissions follow from its attached policies."
		if inst.RoleName != "" {
			credLabel = "role " + inst.RoleName + " credentials"
			roleNote = "Credentials belong to role " + inst.RoleName + "; its privileges follow from the can-escalate/holds-admin edges on that role."
		}
		credID := nodeID + ":imds-creds"
		b.addNode(Node{ID: credID, Kind: NodeResource, Label: credLabel, Type: "aws_iam_instance_credentials", Region: inst.Region})
		credEdge := Edge{
			Src: nodeID, Dst: credID, Kind: EdgeMetadataCreds,
			Detail: "IMDSv2 is not enforced; an SSRF or proxy flaw can read the instance role credentials from IMDSv1",
			PoC:    "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # via SSRF on the exposed instance",
		}
		b.addEdge(credEdge)
		p := b.scorePath(
			"internet-imds-creds:"+inst.ID,
			fmt.Sprintf("Internet-exposed instance %s exposes role credentials via IMDSv1", inst.ID),
			"Public instance allows IMDSv1, so an SSRF/proxy flaw yields the instance's IAM role credentials — the canonical cloud privilege-escalation entry point. "+roleNote,
			0.7, 0.85, "",
			[]Node{b.node(InternetNodeID), b.node(nodeID), b.node(credID)},
			[]Edge{exposeEdge, credEdge},
		)
		b.addPath(applyReachability(p, reach))
	}
}

// instanceReach returns the reachability verdict for an instance, or Unknown
// when no reachability result was supplied.
func (b *builder) instanceReach(inst state.EC2Instance) findings.Reachability {
	if b.rch == nil {
		return findings.ReachUnknown
	}
	return b.rch.Instance(inst)
}

// exposedSecurityGroups: a security group with a world-open ingress rule is an
// internet-reachable surface. The graph's lens is intentionally coarser than the
// per-port check — it asks "reachable from the internet?" not "is the port
// sensitive?" — so it owns no curated port list.
func (b *builder) exposedSecurityGroups(a *state.AWS) {
	for _, sg := range a.SecurityGroups {
		ranges, allPorts := worldOpenRanges(sg)
		if len(ranges) == 0 {
			continue
		}
		nodeID := resourceNodeID("aws_security_group", sg.ID)
		b.addNode(Node{ID: nodeID, Kind: NodeResource, Label: sg.Name, Type: "aws_security_group", Region: sg.Region})
		edge := Edge{
			Src: InternetNodeID, Dst: nodeID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("security group %s allows ingress from 0.0.0.0/0/::0 on %s", sg.ID, strings.Join(ranges, ", ")),
			PoC:    fmt.Sprintf("# any resource attached to %s is reachable on %s from the internet", sg.ID, strings.Join(ranges, ", ")),
		}
		b.addEdge(edge)
		exploit, impact := 0.6, 0.4
		if allPorts {
			exploit, impact = 0.7, 0.6
		}
		b.addPath(b.scorePath(
			"internet-sg:"+sg.ID,
			fmt.Sprintf("Security group %s open to the internet", sg.Name),
			"A world-open ingress rule makes every resource in this group reachable from the internet.",
			exploit, impact, "",
			[]Node{b.node(InternetNodeID), b.node(nodeID)},
			[]Edge{edge},
		))
	}
}

func (b *builder) exposedRDS(a *state.AWS) {
	for _, db := range a.RDSInstances {
		if !db.Public {
			continue
		}
		nodeID := resourceNodeID("aws_db_instance", db.ID)
		b.addNode(Node{ID: nodeID, Kind: NodeResource, Label: db.ID, Type: "aws_db_instance", Region: db.Region})
		edge := Edge{
			Src: InternetNodeID, Dst: nodeID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("RDS instance %s (%s) is publicly accessible", db.ID, db.Engine),
			PoC:    fmt.Sprintf("# resolve the %s endpoint, then: nc -vz <endpoint> <db-port>", db.ID),
		}
		b.addEdge(edge)
		b.addPath(b.scorePath(
			"internet-rds:"+db.ID,
			fmt.Sprintf("Internet-exposed RDS database %s", db.ID),
			"A publicly accessible database is reachable from the internet; only network controls and DB authentication stand between an attacker and the data.",
			0.8, 0.8, "",
			[]Node{b.node(InternetNodeID), b.node(nodeID)},
			[]Edge{edge},
		))
	}
}

func (b *builder) exposedLoadBalancers(a *state.AWS) {
	for _, lb := range a.LoadBalancers {
		if !lb.InternetFacing {
			continue
		}
		plaintext := false
		for _, l := range lb.Listeners {
			if strings.EqualFold(l.Protocol, "HTTP") {
				plaintext = true
				break
			}
		}
		if !plaintext {
			continue
		}
		nodeID := resourceNodeID("aws_lb", lb.ARN)
		b.addNode(Node{ID: nodeID, Kind: NodeResource, Label: lb.Name, Type: "aws_lb", Region: lb.Region, ARN: lb.ARN})
		edge := Edge{
			Src: InternetNodeID, Dst: nodeID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("internet-facing load balancer %s serves a plaintext HTTP listener", lb.Name),
			PoC:    fmt.Sprintf("# traffic to %s is unencrypted and interceptable on the path", lb.Name),
		}
		b.addEdge(edge)
		b.addPath(b.scorePath(
			"internet-lb:"+lb.Name,
			fmt.Sprintf("Internet-facing load balancer %s serves plaintext HTTP", lb.Name),
			"An internet-facing load balancer terminating plaintext HTTP exposes traffic to interception and tampering.",
			0.5, 0.5, "",
			[]Node{b.node(InternetNodeID), b.node(nodeID)},
			[]Edge{edge},
		))
	}
}

func (b *builder) exposedS3(a *state.AWS) {
	for _, bk := range a.S3Buckets {
		if !(bk.ACLPublic || bk.PolicyPublic) || bk.FullyBlocked() {
			continue
		}
		nodeID := resourceNodeID("aws_s3_bucket", bk.Name)
		arn := "arn:aws:s3:::" + bk.Name
		b.addNode(Node{ID: nodeID, Kind: NodeResource, Label: bk.Name, Type: "aws_s3_bucket", Region: bk.Region, ARN: arn})
		edge := Edge{
			Src: InternetNodeID, Dst: nodeID, Kind: EdgeExposedToInternet,
			Detail: fmt.Sprintf("bucket %s is publicly accessible and not fully protected by Block Public Access", bk.Name),
			PoC:    fmt.Sprintf("aws s3api list-objects-v2 --bucket %s --no-sign-request --max-items 5", bk.Name),
		}
		b.addEdge(edge)
		b.addPath(b.scorePath(
			"internet-s3:"+bk.Name,
			fmt.Sprintf("Publicly accessible S3 bucket %s", bk.Name),
			"A public bucket lets unauthenticated callers list and read its objects directly over the internet.",
			0.95, 0.6, "",
			[]Node{b.node(InternetNodeID), b.node(nodeID)},
			[]Edge{edge},
		))
	}
}

// exposedSharedArtifacts: publicly shared snapshots/AMIs are exfiltration paths —
// an attacker in any account can copy the disk image and read its contents.
func (b *builder) exposedSharedArtifacts(a *state.AWS) {
	add := func(rtype, attr string, refs []state.ResourceRef, impact float64) {
		for _, r := range refs {
			nodeID := resourceNodeID(rtype, r.ID)
			b.addNode(Node{ID: nodeID, Kind: NodeResource, Label: r.ID, Type: rtype, Region: r.Region, ARN: r.ARN})
			edge := Edge{
				Src: InternetNodeID, Dst: nodeID, Kind: EdgeExposedToInternet,
				Detail: fmt.Sprintf("%s %s is shared publicly (any AWS account can read it)", rtype, r.ID),
				PoC:    fmt.Sprintf("aws ec2 describe-%s --%s %s   # confirm public share, then copy from an attacker account", attr, snapFlag(rtype), r.ID),
			}
			b.addEdge(edge)
			b.addPath(b.scorePath(
				"public-artifact:"+r.ID,
				fmt.Sprintf("Publicly shared %s %s", rtype, r.ID),
				"A publicly shared disk image or snapshot can be copied by any AWS account and mined for secrets and data.",
				0.7, impact, "",
				[]Node{b.node(InternetNodeID), b.node(nodeID)},
				[]Edge{edge},
			))
		}
	}
	add("aws_ebs_snapshot", "snapshot-attribute", a.PublicEBSSnapshots, 0.7)
	add("aws_ami", "image-attribute", a.PublicAMIs, 0.6)
	add("aws_rds_snapshot", "db-snapshot-attribute", a.PublicRDSSnapshots, 0.8)
}

// rootPrincipal models the account root holding admin via active access keys —
// the privilege dimension's apex target, and not policy-derived, so it is built
// directly rather than through trust analysis.
func (b *builder) rootPrincipal(a *state.AWS) {
	iam := a.IAM
	if !iam.Collected || !iam.RootAccessKeys {
		return
	}
	id := principalNodeID("root")
	b.addNode(Node{ID: id, Kind: NodePrincipal, Label: "root", Type: "aws_account_root"})
	mfa := "and protected by MFA"
	if !iam.RootMFAEnabled {
		mfa = "and NOT protected by MFA"
	}
	edge := Edge{
		Src: id, Dst: id, Kind: EdgeHoldsAdmin,
		Detail: fmt.Sprintf("the account root has active access keys (%s)", mfa),
		PoC:    "# root access keys grant unrestricted account control; if leaked, full compromise follows",
	}
	b.addEdge(edge)
	var floor findings.Severity
	if !iam.RootMFAEnabled {
		floor = findings.SeverityCritical
	}
	b.addPath(b.scorePath(
		"admin-root",
		"Account root holds unrestricted admin via active access keys",
		"Root access keys provide unrestricted, unconditional control of the entire account and should not exist.",
		0.5, 1.0, floor,
		[]Node{b.node(id)},
		[]Edge{edge},
	))
}

// trustEdges builds the IAM trust dimension from the trust analysis: holds-admin
// and can-escalate edges (privilege concentration / escalation) and
// can-assume-role edges (intra-account assume + risky external/federated trust).
func (b *builder) trustEdges(a *state.AWS) {
	if !a.IAM.Collected {
		return
	}
	rep := trust.Analyze(a)

	// Look up users for the console/MFA exploitability signal on admin paths.
	users := map[string]state.IAMUser{}
	for _, u := range a.IAM.Users {
		users[u.Name] = u
	}

	for _, p := range rep.Privs {
		id := principalNodeID(p.Kind + "/" + p.Name)
		b.addNode(Node{ID: id, Kind: NodePrincipal, Label: p.Name, Type: "aws_iam_" + p.Kind})

		if p.Admin {
			detail := fmt.Sprintf("%s %s holds administrator-equivalent permissions", p.Kind, p.Name)
			exploit := 0.4
			if u, ok := users[p.Name]; p.Kind == "user" && ok && u.ConsoleAccess && !u.MFAEnabled {
				detail += "; console login is enabled without MFA"
				exploit = 0.7 // admin reachable by a password-only login
			}
			edge := Edge{Src: id, Dst: id, Kind: EdgeHoldsAdmin, Detail: detail,
				PoC: fmt.Sprintf("aws iam list-attached-%s-policies --%s-name %s", p.Kind, p.Kind, p.Name)}
			b.addEdge(edge)
			b.addPath(b.scorePath(
				"admin-"+p.Kind+":"+p.Name,
				fmt.Sprintf("IAM %s %s holds administrative access", p.Kind, p.Name),
				"An administrator-equivalent principal is a high-value target; weak or password-only auth on it is a direct route to account-wide control.",
				exploit, 0.9, "",
				[]Node{b.node(id)},
				[]Edge{edge},
			))
		}

		if len(p.Privesc) > 0 {
			edge := Edge{Src: id, Dst: id, Kind: EdgeCanEscalate,
				Detail: fmt.Sprintf("%s %s can escalate via: %s", p.Kind, p.Name, strings.Join(p.Privesc, ", ")),
				PoC:    privescPoC(p.Kind, p.Name, p.Privesc)}
			b.addEdge(edge)
			b.addPath(b.scorePath(
				"privesc-"+p.Kind+":"+p.Name,
				fmt.Sprintf("IAM %s %s can escalate to administrator", p.Kind, p.Name),
				"The principal holds privilege-escalation-prone permissions on Resource \"*\", an indirect route to full account control.",
				0.5, 0.85, "",
				[]Node{b.node(id)},
				[]Edge{edge},
			))
		}
	}

	for _, rel := range rep.Assumes {
		b.assumeEdge(rel)
	}
}

// assumeEdge turns one assume relationship into a graph edge (and, for risky
// external/federated/wildcard trust, a scored path).
func (b *builder) assumeEdge(rel trust.AssumeRelation) {
	roleNode := principalNodeID("role/" + rel.RoleName)
	b.addNode(Node{ID: roleNode, Kind: NodePrincipal, Label: rel.RoleName, Type: "aws_iam_role", ARN: rel.RoleARN})

	assumePoC := fmt.Sprintf("aws sts assume-role --role-arn %s --role-session-name s", rel.RoleARN)

	switch rel.Source {
	case trust.SourceIntraAccount:
		// A normal intra-account assume: enrich the graph with the edge, no path.
		src := principalNodeID(shortPrincipal(rel.Principal))
		b.addNode(Node{ID: src, Kind: NodePrincipal, Label: shortPrincipal(rel.Principal), Type: "aws_iam_principal"})
		b.addEdge(Edge{Src: src, Dst: roleNode, Kind: EdgeCanAssume, Detail: rel.Reason, PoC: assumePoC})

	case trust.SourceWildcard:
		edge := Edge{Src: InternetNodeID, Dst: roleNode, Kind: EdgeCanAssume, Detail: rel.Reason, PoC: assumePoC}
		b.addEdge(edge)
		b.addPath(fixedPath(
			"trust-wildcard:"+rel.RoleName,
			fmt.Sprintf("Role %s is assumable by any principal", rel.RoleName),
			"The role's trust policy names Principal \"*\" — anyone who can call sts:AssumeRole inherits its permissions.",
			findings.SeverityCritical, 90,
			[]Node{b.node(InternetNodeID), b.node(roleNode)}, []Edge{edge}))

	case trust.SourceExternal:
		extID := "external:" + rel.Principal
		b.addNode(Node{ID: extID, Kind: NodePrincipal, Label: shortPrincipal(rel.Principal), Type: "external_account"})
		edge := Edge{Src: extID, Dst: roleNode, Kind: EdgeCanAssume, Detail: rel.Reason, PoC: assumePoC}
		b.addEdge(edge)
		// Path id includes the principal: a role trusting two external accounts
		// produces two distinct paths that must not overwrite each other on persist.
		b.addPath(fixedPath(
			"trust-external:"+rel.RoleName+":"+rel.Principal,
			fmt.Sprintf("Role %s trusts an external account", rel.RoleName),
			rel.Reason+" — if that account is attacker-controlled or compromised, the role is too.",
			findings.SeverityHigh, 70,
			[]Node{b.node(extID), b.node(roleNode)}, []Edge{edge}))

	case trust.SourceOIDC:
		edge := Edge{Src: InternetNodeID, Dst: roleNode, Kind: EdgeCanAssume, Detail: rel.Reason, PoC: assumePoC}
		b.addEdge(edge)
		if rel.Risky {
			b.addPath(fixedPath(
				"trust-oidc:"+rel.RoleName+":"+rel.Principal,
				fmt.Sprintf("Role %s trusts an OIDC provider without a subject condition", rel.RoleName),
				rel.Reason+" — any workload the provider issues a token to can assume the role.",
				findings.SeverityHigh, 68,
				[]Node{b.node(InternetNodeID), b.node(roleNode)}, []Edge{edge}))
		}

	case trust.SourceSAML:
		fedID := "federated:" + rel.Principal
		b.addNode(Node{ID: fedID, Kind: NodePrincipal, Label: shortPrincipal(rel.Principal), Type: "saml_provider"})
		b.addEdge(Edge{Src: fedID, Dst: roleNode, Kind: EdgeCanAssume, Detail: rel.Reason, PoC: assumePoC})
	}
}

// privescPoC renders a concrete escalation command for the first matched action.
func privescPoC(kind, name string, actions []string) string {
	if len(actions) == 0 {
		return ""
	}
	return fmt.Sprintf("# %s %s is allowed %s on Resource \"*\" — e.g. attach AdministratorAccess to self",
		kind, name, actions[0])
}

// shortPrincipal trims an ARN to its trailing identity segment for display.
func shortPrincipal(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	if i := strings.LastIndex(arn, ":"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

// node returns the already-added node with the given id (a bare Node{ID} if
// absent), in O(1) via the node index.
func (b *builder) node(id string) Node {
	if n, ok := b.nodes[id]; ok {
		return n
	}
	return Node{ID: id}
}

// worldOpenRanges returns the human-readable port ranges a security group opens
// to the world, and whether any rule opens all ports. Empty if not world-open.
func worldOpenRanges(sg state.SecurityGroup) (ranges []string, allPorts bool) {
	for _, r := range sg.Ingress {
		if !r.OpenV4 && !r.OpenV6 {
			continue
		}
		if r.Protocol == "-1" || (r.FromPort == 0 && r.ToPort == 65535) {
			allPorts = true
			ranges = append(ranges, "all ports")
			continue
		}
		if r.FromPort == r.ToPort {
			ranges = append(ranges, fmt.Sprintf("%s/%d", proto(r.Protocol), r.FromPort))
		} else {
			ranges = append(ranges, fmt.Sprintf("%s/%d-%d", proto(r.Protocol), r.FromPort, r.ToPort))
		}
	}
	sort.Strings(ranges)
	return dedupeStrings(ranges), allPorts
}

func proto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// snapFlag maps a shared-artifact resource type to the describe-* id flag.
func snapFlag(rtype string) string {
	switch rtype {
	case "aws_ami":
		return "image-id"
	case "aws_rds_snapshot":
		return "db-snapshot-identifier"
	default:
		return "snapshot-id"
	}
}
