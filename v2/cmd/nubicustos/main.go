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

	// Register AWS checks (collectors register via the providers/aws import in scan.go).
	_ "github.com/Su1ph3r/nubicustos/internal/checks/aws"
)

const version = "2.0.0-dev"

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
