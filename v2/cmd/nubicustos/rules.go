package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/rules"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage policy-as-code rules (CEL/YAML)",
		Long: "List, validate, and test the declarative CEL/YAML rules evaluated during a\n" +
			"scan: the built-in rules plus any user rules loaded from --rules-dir.",
	}
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesValidateCmd())
	cmd.AddCommand(newRulesTestCmd())
	return cmd
}

// loadRules loads the built-in rules plus any user rules in dir. It returns the
// rules that compiled (built-ins always; user rules that were valid) together
// with any load error, so callers can choose to fail (validate) or proceed
// best-effort (list/test).
func loadRules(dir string) ([]rules.Rule, error) {
	builtin, err := rules.Builtin()
	if err != nil {
		return nil, fmt.Errorf("loading built-in rules: %w", err)
	}
	user, uerr := rules.LoadDir(dir)
	return append(builtin, user...), uerr
}

func newRulesListCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the rules that would be evaluated",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rs, loadErr := loadRules(dir)
			if loadErr != nil {
				// list is informational: report the load problem but still show
				// the rules that did load.
				fmt.Fprintf(os.Stderr, "warning: some rules failed to load:\n%v\n", loadErr)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tPROVIDER\tRESOURCE TYPE\tTITLE")
			for _, r := range rs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Provider, r.ResourceType, r.Title)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&dir, "rules-dir", "", "directory of user rules to include")
	return cmd
}

func newRulesValidateCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Compile and validate rules (built-in + --rules-dir)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rs, loadErr := loadRules(dir)
			// validate fails loud on any problem: compile/parse errors, duplicate
			// ids, or rules targeting an unsupported resource type.
			problems := []error{loadErr, rules.CheckUniqueIDs(rs), rules.CheckResourceTypes(rs)}
			if err := errors.Join(problems...); err != nil {
				return err
			}
			fmt.Printf("%d rule(s) valid\n", len(rs))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "rules-dir", "", "directory of user rules to validate")
	return cmd
}

func newRulesTestCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Evaluate rules against a built-in sample of misconfigured resources",
		Long: "Evaluate the loaded rules against a synthetic sample containing one\n" +
			"deliberately-misconfigured resource of each supported type, and report which\n" +
			"rules fired — a quick way to confirm a rule compiles and matches as intended.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rs, loadErr := loadRules(dir)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "warning: some rules failed to load:\n%v\n", loadErr)
			}
			fs, evalErrs := rules.Evaluate(rs, rules.SampleState())
			for _, e := range evalErrs {
				fmt.Fprintf(os.Stderr, "eval error: %v\n", e)
			}
			matched := map[string]int{}
			for _, f := range fs {
				matched[f.CheckID]++
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "RULE\tMATCHED ON SAMPLE")
			for _, r := range rs {
				status := "no"
				if matched[r.ID] > 0 {
					status = fmt.Sprintf("yes (%d)", matched[r.ID])
				}
				fmt.Fprintf(tw, "%s\t%s\n", r.ID, status)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Printf("\n%d finding(s) on the sample across %d rule(s)\n", len(fs), len(rs))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "rules-dir", "", "directory of user rules to include")
	return cmd
}
