package aws

import (
	"sort"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// sortAffected orders affected items deterministically (by region, then id) so
// aggregate findings are stable across scans regardless of map iteration order.
func sortAffected(items []findings.Affected) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Region != items[j].Region {
			return items[i].Region < items[j].Region
		}
		return items[i].ID < items[j].ID
	})
}
