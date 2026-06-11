// Package portspec is the single source of truth for the sensitive-port catalog
// and the shared port-range parsing used by the AWS, Azure, and GCP network
// checks. It exists so the catalog can't drift between providers (it previously
// had, with one provider listing Memcached and the others not).
package portspec

import (
	"strconv"
	"strings"
)

// Sensitive maps high-risk TCP ports exposed to the internet to a human label.
var Sensitive = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	21:    "FTP",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	1433:  "MSSQL",
	9200:  "Elasticsearch",
	11211: "Memcached",
}

// ParseRange parses a port spec of the form "22" or "20-30" into its inclusive
// bounds. ok is false for any other shape (e.g. "*" or malformed input).
func ParseRange(spec string) (lo, hi int, ok bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, false
	}
	if loStr, hiStr, isRange := strings.Cut(spec, "-"); isRange {
		l, err1 := strconv.Atoi(strings.TrimSpace(loStr))
		h, err2 := strconv.Atoi(strings.TrimSpace(hiStr))
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return l, h, true
	}
	p, err := strconv.Atoi(spec)
	if err != nil {
		return 0, 0, false
	}
	return p, p, true
}

// Covers reports whether a single port spec ("22" or "20-30") includes port.
func Covers(port int, spec string) bool {
	lo, hi, ok := ParseRange(spec)
	return ok && port >= lo && port <= hi
}

// IsAllPorts reports whether a spec covers the entire port space — the literal
// "*" or a range spanning 1..65535 (e.g. "0-65535").
func IsAllPorts(spec string) bool {
	if strings.TrimSpace(spec) == "*" {
		return true
	}
	lo, hi, ok := ParseRange(spec)
	return ok && lo <= 1 && hi >= 65535
}
