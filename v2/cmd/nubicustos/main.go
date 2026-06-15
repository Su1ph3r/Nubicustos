// Command nubicustos is the single cross-platform binary for the v2 rewrite:
// a native cloud-posture engine with embedded storage and a terminal-first UI.
//
// This file wires the cobra root and pulls in the collector/check registries
// via blank imports (their init() functions self-register with the engine).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	// Register every provider's collectors and checks via their init() functions.
	// Registration must not depend on a package being referenced elsewhere (e.g.
	// scan.go calling one symbol per provider) — that is how the k8s collectors
	// were silently absent. Import all of them here, explicitly.
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/k8s"
	_ "github.com/Su1ph3r/nubicustos/internal/checks/rules"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/aws"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/azure"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/gcp"
	_ "github.com/Su1ph3r/nubicustos/internal/providers/k8s"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>" (goreleaser). Defaults to "dev" for local builds.
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "nubicustos",
		Short: "Native cloud security posture engine",
		Long: "Nubicustos scans cloud accounts for security misconfigurations using a native\n" +
			"posture engine — no Docker, no external scanners required — and exports\n" +
			"runtime-proven findings for reporting.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newFindingsCmd())
	root.AddCommand(newExportCmd())
	root.AddCommand(newPathsCmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newPreflightCmd())
	root.AddCommand(newTUICmd())
	root.AddCommand(newWebCmd())
	root.AddCommand(newPluginsCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newMCPCmd())
	root.AddCommand(newComplianceCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "nubicustos", version)
		},
	}
}
