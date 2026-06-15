// Package compliance maps Nubicustos's native checks onto external control
// frameworks (SOC2, PCI-DSS, NIST 800-53) on top of the per-check CIS / AWS
// Well-Architected references the checks already carry.
//
// Rather than hand-map all ~90 check IDs individually (brittle as the catalog
// grows), each check is classified into a small set of control CATEGORIES by its
// id/service/title, and each category is mapped to the equivalent control in
// each framework. This crosswalk is the single place to adjust framework
// mappings, and new checks are covered automatically once classified.
package compliance

import (
	"strings"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// Category is a control theme a check addresses.
type Category string

const (
	CatEncryptionAtRest    Category = "encryption-at-rest"
	CatEncryptionInTransit Category = "encryption-in-transit"
	CatPublicExposure      Category = "public-exposure"
	CatNetworkControl      Category = "network-control"
	CatAccessControl       Category = "access-control"
	CatMFA                 Category = "mfa"
	CatLogging             Category = "logging-monitoring"
	CatSecrets             Category = "secrets-management"
	CatBackup              Category = "backup-recovery"
	CatThreatDetection     Category = "threat-detection"
	CatOther               Category = "other"
)

// Control is a single control in an external framework.
type Control struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
}

// Framework identifiers accepted by the CLI.
const (
	FrameworkSOC2 = "soc2"
	FrameworkPCI  = "pci"
	FrameworkNIST = "nist"
)

// categoryControls maps a category to its equivalent control in each framework.
// Mappings reference SOC2 (Trust Services Criteria), PCI-DSS v4.0 requirements,
// and NIST SP 800-53 Rev.5 controls.
var categoryControls = map[Category]map[string]Control{
	CatEncryptionAtRest: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.1", "Logical access security — protect data at rest"},
		FrameworkPCI:  {FrameworkPCI, "3.5", "Render stored account data unreadable (encryption)"},
		FrameworkNIST: {FrameworkNIST, "SC-28", "Protection of information at rest"},
	},
	CatEncryptionInTransit: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.7", "Restrict transmission of data to authorized parties"},
		FrameworkPCI:  {FrameworkPCI, "4.2", "Strong cryptography during transmission over open networks"},
		FrameworkNIST: {FrameworkNIST, "SC-8", "Transmission confidentiality and integrity"},
	},
	CatPublicExposure: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.6", "Restrict logical access from outside the system boundary"},
		FrameworkPCI:  {FrameworkPCI, "1.3", "Restrict inbound/outbound traffic to the CDE"},
		FrameworkNIST: {FrameworkNIST, "SC-7", "Boundary protection"},
	},
	CatNetworkControl: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.6", "Restrict logical access from outside the system boundary"},
		FrameworkPCI:  {FrameworkPCI, "1.2", "Network security controls configuration"},
		FrameworkNIST: {FrameworkNIST, "SC-7", "Boundary protection"},
	},
	CatAccessControl: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.3", "Manage access based on least privilege"},
		FrameworkPCI:  {FrameworkPCI, "7.2", "Assign access by least privilege and need-to-know"},
		FrameworkNIST: {FrameworkNIST, "AC-6", "Least privilege"},
	},
	CatMFA: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.1", "Logical access security — strong authentication"},
		FrameworkPCI:  {FrameworkPCI, "8.4", "Multi-factor authentication for access"},
		FrameworkNIST: {FrameworkNIST, "IA-2", "Identification and authentication (MFA)"},
	},
	CatLogging: {
		FrameworkSOC2: {FrameworkSOC2, "CC7.2", "Monitor system components for anomalies"},
		FrameworkPCI:  {FrameworkPCI, "10.2", "Implement audit logs for all system components"},
		FrameworkNIST: {FrameworkNIST, "AU-2", "Event logging"},
	},
	CatSecrets: {
		FrameworkSOC2: {FrameworkSOC2, "CC6.1", "Protect authentication credentials"},
		FrameworkPCI:  {FrameworkPCI, "8.3", "Strong authentication / protect credentials"},
		FrameworkNIST: {FrameworkNIST, "IA-5", "Authenticator management"},
	},
	CatBackup: {
		FrameworkSOC2: {FrameworkSOC2, "A1.2", "Recoverability — backup and recovery"},
		FrameworkPCI:  {FrameworkPCI, "12.10", "Incident response and recovery readiness"},
		FrameworkNIST: {FrameworkNIST, "CP-9", "System backup"},
	},
	CatThreatDetection: {
		FrameworkSOC2: {FrameworkSOC2, "CC7.1", "Detect and respond to vulnerabilities/threats"},
		FrameworkPCI:  {FrameworkPCI, "11.3", "Vulnerability detection and management"},
		FrameworkNIST: {FrameworkNIST, "SI-4", "System monitoring / RA-5 vulnerability scanning"},
	},
}

// Classify assigns a check to a control category from its id, service, and title.
// The order matters: more specific themes are tested before broader ones.
func Classify(spec findings.CheckSpec) Category {
	s := strings.ToLower(spec.ID + " " + spec.Service + " " + spec.Title)
	switch {
	case has(s, "mfa"):
		return CatMFA
	case has(s, "secret", "exposed_secret"):
		return CatSecrets
	case hasTransitEncryption(s):
		return CatEncryptionInTransit
	case has(s, "encrypt", "unencrypted", "rotation"):
		return CatEncryptionAtRest
	case has(s, "public", "publicly", "anonymous", "open_ingress", "allow_all", "blob_public", "world", "dangling"):
		return CatPublicExposure
	case has(s, "nsg", "firewall", "security_group", "network", "imdsv2", "flow_logs"):
		return CatNetworkControl
	case has(s, "log", "trail", "audit", "monitor", "config_not_recording"):
		return CatLogging
	case has(s, "guardduty", "defender", "scan_on_push", "shielded"):
		return CatThreatDetection
	case has(s, "backup", "deletion_protection", "soft_delete", "purge"):
		return CatBackup
	case has(s, "iam", "rbac", "role", "policy", "admin", "privilege", "password", "primitive", "trust", "federated", "multi_tenant", "local_auth", "shared_key", "default_sa"):
		return CatAccessControl
	default:
		return CatOther
	}
}

func hasTransitEncryption(s string) bool {
	return (has(s, "tls", "https", "ssl", "ftps") && !has(s, "encrypt_at_rest")) || has(s, "not_https_only", "min_tls", "ssl_not_required")
}

func has(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ControlFor returns the control a category maps to in framework (ok=false when
// the category has no mapped control, e.g. CatOther).
func ControlFor(cat Category, framework string) (Control, bool) {
	if m, ok := categoryControls[cat]; ok {
		if c, ok := m[framework]; ok {
			return c, true
		}
	}
	return Control{}, false
}
