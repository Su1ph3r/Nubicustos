// Package graph builds the in-process attack-path graph that replaces the v1
// Neo4j + PMapper + CloudMapper stack. Nodes are the internet, cloud resources,
// and IAM principals; edges are concrete, PoC-bearing relationships (an exposed
// resource reachable from the internet, a principal that holds administrative
// access). Paths are runnable, step-by-step exploit narratives scored 0-100.
//
// The builder derives edges only from facts the collectors actually gather.
// Assume-role and privilege-escalation chains require IAM role trust policies
// and policy documents (the federation/trust collector, plan §9.3), which are
// not collected yet; the EdgeCanAssume / EdgeCanEscalate kinds are reserved so
// those edges slot in without reworking the model.
package graph

import (
	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// NodeKind enumerates the kinds of vertices in the graph.
type NodeKind string

const (
	NodeInternet  NodeKind = "internet"
	NodeResource  NodeKind = "resource"
	NodePrincipal NodeKind = "principal"
)

// EdgeKind enumerates the relationships between nodes. CanAssume and CanEscalate
// are defined now but emitted only once the trust/policy collector exists.
type EdgeKind string

const (
	EdgeExposedToInternet EdgeKind = "exposed-to-internet"
	EdgeMetadataCreds     EdgeKind = "metadata-credential-exposure"
	EdgeHoldsAdmin        EdgeKind = "holds-admin"
	EdgeCanAssume         EdgeKind = "can-assume-role" // reserved (plan §9.3)
	EdgeCanEscalate       EdgeKind = "can-escalate"    // reserved (plan §9.3)
)

// InternetNodeID is the stable id of the singleton internet node.
const InternetNodeID = "internet"

// Node is a vertex: the internet, a cloud resource, or an IAM principal.
type Node struct {
	ID     string   `json:"id"` // stable: kind-scoped (e.g. "resource:aws_ec2_instance:i-123")
	Kind   NodeKind `json:"kind"`
	Label  string   `json:"label"`
	Type   string   `json:"type,omitempty"` // resource/principal subtype
	Region string   `json:"region,omitempty"`
	ARN    string   `json:"arn,omitempty"`
}

// Edge is a directed, PoC-bearing relationship between two nodes.
type Edge struct {
	Src    string   `json:"src"` // node ID
	Dst    string   `json:"dst"` // node ID
	Kind   EdgeKind `json:"kind"`
	Detail string   `json:"detail,omitempty"`
	PoC    string   `json:"poc,omitempty"` // concrete command proving this hop
}

// Path is an ordered, scored chain of nodes/edges — a runnable exploit narrative.
type Path struct {
	ID        string                `json:"id"`
	Title     string                `json:"title"`
	Score     int                   `json:"score"`    // 0-100, exploitability x impact (+ floor)
	Severity  findings.Severity     `json:"severity"` // derived from Score and an intrinsic floor
	Reachable findings.Reachability `json:"reachable,omitempty"`
	Rationale string                `json:"rationale,omitempty"`
	Nodes     []Node                `json:"nodes"`
	Edges     []Edge                `json:"edges"`
}

// Graph is the full attack-path graph for one scan.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Paths []Path `json:"paths"`
}

// Principals returns the principal-kind nodes (for persistence to the
// principals table and for callers that want the identity inventory).
func (g *Graph) Principals() []Node {
	var out []Node
	for _, n := range g.Nodes {
		if n.Kind == NodePrincipal {
			out = append(out, n)
		}
	}
	return out
}
