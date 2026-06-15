// Package plugins is the OPTIONAL external-tool integration (plan §5). It runs
// well-known read-only scanners (trivy, grype, checkov, terrascan, kube-bench)
// only if their binary is present, and normalizes their output into the shared
// Finding model — specialized coverage without making any tool a hard dependency.
package plugins

// Format identifies a tool's output schema, dispatched to a parser by Run.
type Format string

const (
	FormatTrivy     Format = "trivy"
	FormatGrype     Format = "grype"
	FormatCheckov   Format = "checkov"
	FormatTerrascan Format = "terrascan"
	FormatKubeBench Format = "kube-bench"
)

// Manifest is a declarative descriptor for an external tool. Args is built from
// a fixed template plus the operator-supplied target, and is passed to exec as
// separate argv elements (never a shell), so there is no command-injection path.
type Manifest struct {
	Name    string // tool name as used on the CLI (e.g. "trivy")
	Binary  string // executable looked up on PATH
	Service string // finding service/category (e.g. "vuln", "iac", "k8s-bench")
	Format  Format // output schema → parser
	// Args returns the argv (excluding the binary) for the given target. Tools
	// that take no target (e.g. kube-bench, which scans the local node) ignore it.
	Args func(target string) []string
}

// Builtin is the set of supported tools. Each invocation requests JSON on stdout.
var Builtin = []Manifest{
	{
		Name: "trivy", Binary: "trivy", Service: "vuln", Format: FormatTrivy,
		Args: func(target string) []string {
			return []string{"fs", "--quiet", "--format", "json", target}
		},
	},
	{
		Name: "grype", Binary: "grype", Service: "vuln", Format: FormatGrype,
		Args: func(target string) []string {
			return []string{"-o", "json", target}
		},
	},
	{
		Name: "checkov", Binary: "checkov", Service: "iac", Format: FormatCheckov,
		Args: func(target string) []string {
			return []string{"--quiet", "--compact", "-o", "json", "-d", target}
		},
	},
	{
		Name: "terrascan", Binary: "terrascan", Service: "iac", Format: FormatTerrascan,
		Args: func(target string) []string {
			return []string{"scan", "-o", "json", "-d", target}
		},
	},
	{
		Name: "kube-bench", Binary: "kube-bench", Service: "k8s-bench", Format: FormatKubeBench,
		Args: func(string) []string {
			return []string{"--json"}
		},
	},
}

// Lookup returns the built-in manifest for a tool name (ok=false if unknown).
func Lookup(name string) (Manifest, bool) {
	for _, m := range Builtin {
		if m.Name == name {
			return m, true
		}
	}
	return Manifest{}, false
}
