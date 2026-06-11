package rules

import (
	"errors"
	"fmt"
	"sort"
)

// supportedTypes is the set of resource types the flattener can emit. A rule
// targeting a type outside this set can never match, so it is surfaced rather
// than silently never firing. Keep in sync with Flatten in resources.go.
var supportedTypes = map[string]bool{
	"aws_s3_bucket":         true,
	"aws_rds_instance":      true,
	"aws_iam_user":          true,
	"aws_security_group":    true,
	"azure_storage_account": true,
	"azure_key_vault":       true,
	"gcp_storage_bucket":    true,
	"k8s_pod":               true,
}

// SupportedResourceTypes returns the resource types rules may target, sorted.
func SupportedResourceTypes() []string {
	out := make([]string, 0, len(supportedTypes))
	for t := range supportedTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// CheckUniqueIDs returns an error if any rule id appears more than once across
// the assembled set (built-in + user). Duplicate ids would produce colliding
// finding ids for the same resource.
func CheckUniqueIDs(rs []Rule) error {
	seen := make(map[string]struct{}, len(rs))
	var errs []error
	for _, r := range rs {
		if _, dup := seen[r.ID]; dup {
			errs = append(errs, fmt.Errorf("duplicate rule id %q", r.ID))
			continue
		}
		seen[r.ID] = struct{}{}
	}
	return errors.Join(errs...)
}

// CheckResourceTypes returns an error naming any rule whose resource_type the
// engine does not support (the rule would never match).
func CheckResourceTypes(rs []Rule) error {
	var errs []error
	for _, r := range rs {
		if !supportedTypes[r.ResourceType] {
			errs = append(errs, fmt.Errorf("rule %q targets unsupported resource_type %q (it will never match)", r.ID, r.ResourceType))
		}
	}
	return errors.Join(errs...)
}
