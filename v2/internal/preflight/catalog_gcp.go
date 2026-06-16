package preflight

// nubicustosGCPPermissions is the authoritative set of GCP IAM permissions the
// native GCP collectors and discovery invoke. Derived from the API calls in
// internal/providers/gcp and internal/providers/gcp/gcp.go (project discovery).
// Keep in sync when a collector adds an API call.
//
// All are project-level permissions, so they can be checked in a single
// resourcemanager Projects.TestIamPermissions call — GCP's authoritative
// "which of these can I do" API.
var nubicustosGCPPermissions = []string{
	// discovery + project IAM posture
	"resourcemanager.projects.get",
	"resourcemanager.projects.getIamPolicy",
	// Cloud Storage posture
	"storage.buckets.list",
	"storage.buckets.getIamPolicy",
	// VPC firewall posture
	"compute.firewalls.list",
	// control-plane secrets (§9.2): Cloud Function env vars + instance metadata
	"cloudfunctions.functions.list",
	"compute.instances.list",
	// Cloud SQL posture
	"cloudsql.instances.list",
	// Cloud KMS posture (key rotation + public IAM)
	"cloudkms.keyRings.list",
	"cloudkms.cryptoKeys.list",
	"cloudkms.cryptoKeys.getIamPolicy",
	// GKE posture
	"container.clusters.list",
	// Monitoring (CIS 2.x: log metrics + alert policies)
	"logging.logMetrics.list",
	"monitoring.alertPolicies.list",
	// Workload-identity federation (cross-cloud trust): pools + their providers
	"iam.workloadIdentityPools.list",
	"iam.workloadIdentityPoolProviders.list",
}

// GCPTools is the requirement catalog for GCP scanning. RequiredManagedPolicies
// carries predefined GCP role names here (the remediator grants them by name);
// roles/iam.securityReviewer covers the getIamPolicy + list reads and
// roles/viewer covers the remaining project/compute reads.
var GCPTools = []Tool{
	{
		Key: "nubicustos", Name: "Nubicustos (native GCP checks)",
		Description:             "The built-in read-only GCP posture engine (storage, firewall, project IAM)",
		RequiredManagedPolicies: []string{"roles/iam.securityReviewer", "roles/viewer"},
		RequiredActions:         nubicustosGCPPermissions,
		RemediationPolicyName:   "NubicustosGcpReadRole",
	},
}

// GCPToolByKey returns the GCP catalog entry for key (ok=false if unknown).
func GCPToolByKey(key string) (Tool, bool) {
	for _, t := range GCPTools {
		if t.Key == key {
			return t, true
		}
	}
	return Tool{}, false
}
