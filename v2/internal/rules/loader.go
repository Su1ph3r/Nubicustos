package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
)

// isRuleFile reports whether a filename is a YAML rule file.
func isRuleFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// LoadFS loads and compiles every rule file under root in fsys (used for the
// embedded built-in rules).
func LoadFS(fsys fs.FS, root string) ([]Rule, error) {
	env, err := ruleEnv()
	if err != nil {
		return nil, err
	}
	var rules []Rule
	err = fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isRuleFile(path) {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		loaded, err := compileFile(env, path, data)
		if err != nil {
			return err
		}
		rules = append(rules, loaded...)
		return nil
	})
	return rules, err
}

// LoadDir loads and compiles every rule file in a user directory. A missing
// directory is not an error (the user simply supplied none).
//
// Failures are isolated per file: a single malformed file does not prevent the
// other (valid) files from loading. The successfully-compiled rules are returned
// together with a joined error naming every file that failed, so one typo never
// silently disables an operator's whole rule set.
func LoadDir(dir string) ([]Rule, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading rules dir %s: %w", dir, err)
	}
	env, err := ruleEnv()
	if err != nil {
		return nil, err
	}
	var rules []Rule
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !isRuleFile(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", path, err))
			continue
		}
		loaded, err := compileFile(env, path, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, loaded...)
	}
	return rules, errors.Join(errs...)
}

// compileFile parses a file's rules and compiles each, tagging errors with the
// file path. Cross-file id uniqueness is enforced separately on the assembled
// set via CheckUniqueIDs.
func compileFile(env *cel.Env, path string, data []byte) ([]Rule, error) {
	parsed, err := parseRules(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for i := range parsed {
		if err := parsed[i].compile(env); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return parsed, nil
}
