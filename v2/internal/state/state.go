// Package state holds the normalized cloud configuration that collectors gather
// and checks evaluate. It is the in-memory boundary between the "read the cloud"
// phase (providers) and the "judge the cloud" phase (checks), so neither side
// has to know about the other.
//
// Collectors run concurrently, so all mutating accessors are mutex-guarded.
package state

import (
	"net"
	"strings"
	"sync"
	"time"
)

// --- S3 ---------------------------------------------------------------------

// S3Bucket is the collected posture of a single S3 bucket.
type S3Bucket struct {
	Name                  string
	Region                string
	HasPublicAccessBlock  bool
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
	ACLPublic             bool
	PolicyPublic          bool
}

// FullyBlocked reports whether all four Public Access Block controls are on.
func (b S3Bucket) FullyBlocked() bool {
	return b.HasPublicAccessBlock &&
		b.BlockPublicAcls && b.IgnorePublicAcls &&
		b.BlockPublicPolicy && b.RestrictPublicBuckets
}

// --- IAM (global) -----------------------------------------------------------

// AccessKey is one IAM access key's age/status.
type AccessKey struct {
	ID      string
	Active  bool
	AgeDays int
}

// IAMUser is the collected posture of a single IAM user.
type IAMUser struct {
	Name          string
	ConsoleAccess bool // has a login profile (console password)
	MFAEnabled    bool
	AdminAttached bool // AdministratorAccess managed policy attached directly
	AccessKeys    []AccessKey
	Policies      []PolicyDocument // attached + inline permission policies (for privesc analysis)
}

// PolicyStatement is a normalized IAM policy statement. The same shape carries
// both permission policies (Actions/Resources) and trust policies (the Principal
// fields), so one parser and one analyzer cover both.
type PolicyStatement struct {
	Effect        string   // Allow | Deny
	Actions       []string // may include "*" or service wildcards like "iam:*"
	Resources     []string // may include "*"
	AWSPrincipals []string // trust policy: account/role/user ARNs, or "*"
	Federated     []string // trust policy: OIDC/SAML provider ARNs
	Services      []string // trust policy: service principals (e.g. ec2.amazonaws.com)
	ConditionKeys []string // flattened condition keys present (e.g. "oidc:sub")
}

// PolicyDocument is a parsed IAM policy (permission or trust).
type PolicyDocument struct {
	Statements []PolicyStatement
}

// IAMRole is the collected posture of an IAM role, including who may assume it.
type IAMRole struct {
	Name          string
	ARN           string
	TrustPolicy   PolicyDocument   // AssumeRolePolicyDocument: who may assume this role
	AdminAttached bool             // AdministratorAccess attached directly
	Policies      []PolicyDocument // attached + inline permission policies (for privesc analysis)
}

// PasswordPolicy captures the account password policy (Present=false if none).
type PasswordPolicy struct {
	Present        bool
	MinLength      int
	RequireSymbols bool
	RequireNumbers bool
	RequireUpper   bool
	RequireLower   bool
	MaxAgeDays     int // 0 = no expiration configured
}

// IAMState is the account-wide IAM posture.
type IAMState struct {
	Collected      bool
	RootMFAEnabled bool
	RootAccessKeys bool
	PasswordPolicy PasswordPolicy
	Users          []IAMUser
	Roles          []IAMRole
}

// --- EC2 (regional) ---------------------------------------------------------

// IngressRule is a single inbound security-group rule. OpenV4/OpenV6 are
// retained as the world-open shortcut every existing consumer uses; the CIDR and
// source-group lists are the full source set, populated alongside them so
// resource-level reachability can reason about non-world sources (a peer VPC's
// CIDR, another security group).
type IngressRule struct {
	Protocol  string // tcp, udp, icmp, -1 (all)
	FromPort  int
	ToPort    int
	OpenV4    bool     // an IPv4 source is 0.0.0.0/0
	OpenV6    bool     // an IPv6 source is ::/0
	IPv4CIDRs []string // all IPv4 source CIDRs (includes 0.0.0.0/0 when OpenV4)
	IPv6CIDRs []string // all IPv6 source CIDRs (includes ::/0 when OpenV6)
	SourceSGs []string // source security-group ids (UserIdGroupPairs)
}

// SecurityGroup is the collected ingress posture of a security group.
type SecurityGroup struct {
	ID      string
	Name    string
	Region  string
	VPCID   string // owning VPC (for resolving cross-VPC vs intra-VPC source-SG references)
	Ingress []IngressRule
}

// WorldOpen reports whether the group has any ingress rule open to the whole
// internet (0.0.0.0/0 or ::/0). Shared by the checks, the attack-path graph,
// and the reachability solver so the predicate has one definition.
func (g SecurityGroup) WorldOpen() bool {
	for _, r := range g.Ingress {
		if r.OpenV4 || r.OpenV6 {
			return true
		}
	}
	return false
}

// EC2Instance is the collected posture of an instance.
type EC2Instance struct {
	ID                 string
	Region             string
	PublicIP           string
	IMDSv2Required     bool
	VPCID              string
	SubnetID           string
	SecurityGroupIDs   []string
	InstanceProfileARN string // attached instance profile (carries the IAM role)
	RoleName           string // resolved role name behind the instance profile, if known
}

// Subnet is the collected network placement of a subnet, used by the
// reachability solver to decide whether a resource is internet-reachable.
type Subnet struct {
	ID                  string
	Region              string
	VPCID               string
	RouteTableID        string // associated route table id (resolved; main if none explicit)
	MapPublicIPOnLaunch bool
}

// RouteTable records whether a route table provides a default route to an
// internet gateway (the topological condition for internet reachability).
type RouteTable struct {
	ID       string
	Region   string
	VPCID    string
	Main     bool
	IGWRoute bool // has a 0.0.0.0/0 or ::/0 route targeting an internet gateway
	// PeeringIDs are the VPC-peering connection ids (pcx-...) this table routes
	// to, i.e. the peers the table's VPC can send traffic to. Used by the
	// reachability solver to find lateral exposure across a peering.
	PeeringIDs []string
}

// VPCPeering is one VPC-peering connection: the two VPCs it bridges and whether
// it is active. Combined with route tables that target it, it lets the
// reachability solver discover a private VPC that is reachable from an
// internet-exposed one across the peering.
type VPCPeering struct {
	ID     string // pcx-...
	Region string
	VPCA   string // requester VPC id
	VPCB   string // accepter VPC id
	Active bool   // status code is "active"
}

// EBSVolume is the collected encryption posture of a volume.
type EBSVolume struct {
	ID        string
	Region    string
	Encrypted bool
}

// --- Lambda (regional) ------------------------------------------------------

// LambdaFunction is the collected public-exposure posture of a Lambda function.
type LambdaFunction struct {
	Name         string
	Region       string
	PublicURL    bool // a function URL with AuthType NONE (anonymous invoke over HTTPS)
	PublicPolicy bool // resource policy allows Principal "*" with no restricting condition
}

// MessagingResource is the collected public-exposure posture of an SNS topic or
// SQS queue (both expose access via a resource policy).
type MessagingResource struct {
	Service      string // "sns" | "sqs"
	Name         string
	ID           string // topic ARN / queue URL
	Region       string
	PublicPolicy bool // resource policy allows Principal "*" with no restricting condition
}

// RedshiftCluster is the collected posture of a Redshift cluster.
type RedshiftCluster struct {
	ID        string
	Region    string
	Public    bool // publicly accessible (reachable outside the VPC)
	Encrypted bool // data at rest encrypted
}

// ECRRepository is the collected posture of an Elastic Container Registry repo.
type ECRRepository struct {
	Name         string
	Region       string
	ScanOnPush   bool // image vulnerability scanning on push enabled
	PublicPolicy bool // repository policy allows Principal "*" with no condition
}

// ClassicELB is the collected listener posture of a classic (v1) Elastic Load
// Balancer.
type ClassicELB struct {
	Name           string
	Region         string
	InternetFacing bool
	InsecurePorts  []int32 // front-end listener ports using cleartext HTTP/TCP
}

// EFSFileSystem is the collected encryption posture of an EFS file system.
type EFSFileSystem struct {
	ID        string
	Region    string
	Encrypted bool
}

// ElasticacheGroup is the collected encryption posture of an ElastiCache (Redis)
// replication group.
type ElasticacheGroup struct {
	ID                 string
	Region             string
	AtRestEncrypted    bool
	InTransitEncrypted bool
}

// DynamoDBTable is the collected backup posture of a DynamoDB table.
type DynamoDBTable struct {
	Name        string
	Region      string
	PITREnabled bool // point-in-time recovery enabled
}

// --- RDS (regional) ---------------------------------------------------------

// RDSInstance is the collected posture of an RDS instance.
type RDSInstance struct {
	ID                 string
	Region             string
	Engine             string
	Public             bool
	Encrypted          bool
	BackupRetention    int
	DeletionProtection bool
	Endpoint           string // DNS address the engine listens on (empty if not yet available)
	Port               int    // engine port (0 if unknown)
}

// --- CloudWatch monitoring (CIS log-metric-filter + alarm) ------------------

// LogMetricFilter is a CloudWatch Logs metric filter and the metric names it
// emits, used to verify CIS monitoring coverage (a filter for a sensitive event
// plus an alarm on its metric).
type LogMetricFilter struct {
	Pattern     string
	MetricNames []string
	Region      string
}

// --- CloudTrail (regional, account-derived) ---------------------------------

// CloudTrailTrail is the collected posture of a trail (deduped by ARN).
type CloudTrailTrail struct {
	ARN           string
	Name          string
	HomeRegion    string
	MultiRegion   bool
	IsLogging     bool
	LogValidation bool
	KMSEncrypted  bool
}

// --- VPC + snapshot exposure (regional) -------------------------------------

// ResourceRef is a lightweight reference to a cloud resource, used by aggregate
// exposure findings (public snapshots, AMIs).
type ResourceRef struct {
	ID     string
	Region string
	ARN    string
}

// VPCInfo records whether a VPC has flow logging enabled.
type VPCInfo struct {
	ID         string
	Region     string
	HasFlowLog bool
}

// --- KMS (regional) ---------------------------------------------------------

// KMSKey is the collected posture of a KMS key. Only customer-managed keys are
// actionable (AWS-managed keys rotate automatically and cannot be configured).
type KMSKey struct {
	ID              string
	Region          string
	CustomerManaged bool
	Enabled         bool
	RotationEnabled bool
}

// --- AWS Config / GuardDuty (regional, account services) --------------------

// ConfigStatus is the per-region AWS Config recorder posture.
type ConfigStatus struct {
	Recording    bool
	AllSupported bool
}

// --- Secrets Manager (regional) ---------------------------------------------

// SecretInfo is the rotation posture of a Secrets Manager secret.
type SecretInfo struct {
	ARN             string
	Name            string
	Region          string
	RotationEnabled bool
}

// --- ELB / ELBv2 (regional) -------------------------------------------------

// ELBListener is one load-balancer listener's protocol/TLS posture.
type ELBListener struct {
	Protocol  string // HTTP | HTTPS | TCP | TLS | UDP
	Port      int
	SSLPolicy string // negotiation policy name for TLS listeners
}

// LoadBalancer is the collected posture of an ALB/NLB.
type LoadBalancer struct {
	ARN               string
	Name              string
	Region            string
	InternetFacing    bool
	AccessLogsEnabled bool
	Listeners         []ELBListener
}

// --- ACM (regional) ---------------------------------------------------------

// Certificate is the collected posture of an ACM certificate.
type Certificate struct {
	ARN          string
	Region       string
	DomainName   string
	Status       string
	NotAfter     time.Time
	Expired      bool
	DaysToExpiry int
}

// SecretHit is one secret detected on a cloud control-plane text surface (plan
// §9.2). It carries only scrubbed material — a masked rendering and the last four
// characters, never the raw value — so nothing downstream can leak the secret.
type SecretHit struct {
	Detector string // detector id, e.g. "aws_access_key_id", "generic_secret"
	Kind     string // human label
	Surface  string // where it was found, e.g. "lambda_env", "ec2_userdata", "azure_appservice_setting"
	Resource string // owning resource (function name, instance id, parameter name, web app)
	Account  string // owning account / subscription / project (empty for AWS, which scopes by AWS.Account)
	Region   string
	Locator  string // secret-safe field locator (env var name, "userdata"), never the value
	Masked   string // masked rendering (last 4 only)
	LastFour string
	Entropy  float64
}

// Route53Record is a collected DNS record relevant to subdomain-takeover
// analysis: a CNAME or an alias A/AAAA record and the target it points at. Plain
// A/AAAA records to literal IPs are not collected — only records that delegate
// to another hostname (where the target can disappear out from under the record)
// are takeover candidates.
type Route53Record struct {
	ZoneID string // hosted zone id (e.g. Z123ABC)
	Zone   string // hosted zone name (e.g. example.com.)
	Name   string // record name (e.g. app.example.com.)
	Type   string // CNAME | A | AAAA
	Target string // CNAME value, or the alias AliasTarget DNSName
	Alias  bool   // true for an alias (A/AAAA) record, false for a plain CNAME
}

// --- aggregate --------------------------------------------------------------

// AWS is the collected AWS-side state for one account.
type AWS struct {
	Account string

	S3Buckets []S3Bucket
	IAM       IAMState

	SecurityGroups         []SecurityGroup
	Instances              []EC2Instance
	Volumes                []EBSVolume
	Subnets                []Subnet
	RouteTables            []RouteTable
	EBSEncryptionByDefault map[string]bool // region -> enabled

	RDSInstances     []RDSInstance
	Lambdas          []LambdaFunction
	Messaging        []MessagingResource
	Redshift         []RedshiftCluster
	ECRRepos         []ECRRepository
	LogMetricFilters []LogMetricFilter
	AlarmedMetrics   []string // CloudWatch metric names that have an alarm
	EFS              []EFSFileSystem
	Elasticache      []ElasticacheGroup
	DynamoDB         []DynamoDBTable
	ClassicELBs      []ClassicELB
	Trails           []CloudTrailTrail

	KMSKeys                  []KMSKey
	ConfigByRegion           map[string]ConfigStatus // region -> recorder status
	GuardDutyEnabledByRegion map[string]bool         // region -> has an enabled detector

	VPCs               []VPCInfo
	Peerings           []VPCPeering
	PublicEBSSnapshots []ResourceRef
	PublicAMIs         []ResourceRef
	PublicRDSSnapshots []ResourceRef

	Secrets        []SecretInfo
	LoadBalancers  []LoadBalancer
	Certificates   []Certificate
	Route53Records []Route53Record
	SecretHits     []SecretHit
}

// --- Azure ------------------------------------------------------------------

// StorageAccount is the collected posture of an Azure storage account.
type StorageAccount struct {
	Name                   string
	ResourceGroup          string
	Subscription           string
	Location               string
	AllowBlobPublicAccess  bool   // account permits anonymous blob/container access
	HTTPSOnly              bool   // EnableHTTPSTrafficOnly
	MinTLSVersion          string // e.g. "TLS1_2"
	NetworkDefaultAllow    bool   // network rule set default action == Allow (open to all networks)
	SharedKeyAccessAllowed bool   // shared-key (account-key) auth permitted; nil from Azure means allowed
}

// NSGRule is a single inbound/outbound security rule on a network security group.
type NSGRule struct {
	Name      string
	Direction string // Inbound | Outbound
	Access    string // Allow | Deny
	Protocol  string // Tcp | Udp | * ...
	Priority  int
	DestPorts []string // destination ports/ranges (e.g. "22", "0-65535", "*")
	Sources   []string // source prefixes: "*", "Internet", "0.0.0.0/0", CIDRs
}

// OpenToInternet reports whether the rule allows inbound traffic from the whole
// internet — any source that is "*", the Internet service tag, "any", or a
// zero-length-prefix CIDR in either family — on an Allow rule.
func (r NSGRule) OpenToInternet() bool {
	if !strings.EqualFold(r.Direction, "Inbound") || !strings.EqualFold(r.Access, "Allow") {
		return false
	}
	for _, s := range r.Sources {
		if sourceIsInternet(s) {
			return true
		}
	}
	return false
}

// sourceIsInternet classifies an NSG source prefix as internet-equivalent. It
// matches the "*"/"Internet"/"any" tags (case-insensitively) and any CIDR whose
// prefix length is zero (e.g. 0.0.0.0/0, ::/0, or any "<addr>/0").
func sourceIsInternet(s string) bool {
	s = strings.TrimSpace(s)
	if s == "*" || strings.EqualFold(s, "Internet") || strings.EqualFold(s, "any") {
		return true
	}
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		ones, _ := ipnet.Mask.Size()
		return ones == 0
	}
	return false
}

// NetworkSecurityGroup is the collected rule posture of an Azure NSG.
type NetworkSecurityGroup struct {
	ID            string // ARM resource id (for NIC/subnet association in reachability)
	Name          string
	ResourceGroup string
	Subscription  string
	Location      string
	Rules         []NSGRule
}

// AzureNIC is a network interface's reachability-relevant attachment: whether it
// has a public IP, the NSG bound directly to it, and the subnet it sits in
// (whose NSG also applies). Used by the Azure reachability solver (§9.5).
type AzureNIC struct {
	Name        string
	HasPublicIP bool
	NSGID       string // NIC-level NSG (empty if none)
	SubnetID    string
}

// AzureSubnetNSG maps a subnet to the NSG bound to it (subnet-level NSGs apply to
// every NIC in the subnet).
type AzureSubnetNSG struct {
	SubnetID string
	NSGID    string
}

// KeyVault is the collected posture of an Azure key vault.
type KeyVault struct {
	Name                string
	ResourceGroup       string
	Subscription        string
	Location            string
	SoftDeleteEnabled   bool
	PurgeProtection     bool
	NetworkDefaultAllow bool // network ACL default action == Allow
}

// WebApp is the collected posture of an Azure App Service / Function web app.
type WebApp struct {
	Name          string
	ResourceGroup string
	Subscription  string
	Location      string
	HTTPSOnly     bool   // configures the site to accept only HTTPS requests
	MinTLSVersion string // SiteConfig minimum TLS version, e.g. "1.0", "1.1", "1.2"
	FtpsState     string // "AllAllowed" (plain FTP permitted) | "FtpsOnly" | "Disabled"
}

// SQLFirewallRule is a single server-level firewall rule on an Azure SQL server.
// The special range 0.0.0.0-0.0.0.0 is the "allow all Azure services" rule;
// 0.0.0.0-255.255.255.255 opens the server to the entire internet.
type SQLFirewallRule struct {
	Name    string
	StartIP string
	EndIP   string
}

// OpensToInternet reports whether the rule spans the whole public range
// (0.0.0.0 through 255.255.255.255), exposing the server to every host online.
func (r SQLFirewallRule) OpensToInternet() bool {
	return r.StartIP == "0.0.0.0" && r.EndIP == "255.255.255.255"
}

// SQLServer is the collected posture of an Azure SQL logical server.
type SQLServer struct {
	Name                string
	ResourceGroup       string
	Subscription        string
	Location            string
	PublicNetworkAccess bool   // public endpoint enabled (reachable outside the VNet)
	MinTLSVersion       string // "None" | "1.0" | "1.1" | "1.2"
	FirewallRules       []SQLFirewallRule
}

// CosmosAccount is the collected posture of an Azure Cosmos DB account.
type CosmosAccount struct {
	Name                string
	ResourceGroup       string
	Subscription        string
	Location            string
	PublicNetworkAccess bool // public endpoint enabled
	LocalAuthDisabled   bool // key-based (local) auth disabled — Entra-only is the hardened state
}

// DefenderPlan is one Microsoft Defender for Cloud plan and its pricing tier.
type DefenderPlan struct {
	Subscription string
	Name         string // resource-type plan, e.g. "VirtualMachines", "StorageAccounts"
	Tier         string // "Free" | "Standard"
}

// AzureCustomRole is a custom RBAC role definition and whether its permissions
// include a wildcard action.
type AzureCustomRole struct {
	Name           string
	Subscription   string
	WildcardAction bool // an Actions entry is "*" (grants every control-plane action)
}

// AzureFederatedCred is one workload-identity federated credential on an app
// registration: an external OIDC issuer trusted to obtain tokens as the app.
type AzureFederatedCred struct {
	Name    string
	Issuer  string
	Subject string
}

// AzureAppRegistration is the collected Entra ID (Azure AD) app-registration
// posture relevant to the trust surface (plan §9.3).
type AzureAppRegistration struct {
	DisplayName          string
	AppID                string
	MultiTenant          bool // signInAudience admits accounts outside this tenant
	HasExpiredCredential bool // a password/key credential's expiry is in the past
	FederatedCreds       []AzureFederatedCred
}

// AzureMonitor is a subscription's monitoring posture: which sensitive
// operations have an enabled activity-log alert (CIS Azure section 5.2).
type AzureMonitor struct {
	Subscription      string
	AlertsReadOK      bool     // the activity-log-alerts read succeeded (else don't judge)
	AlertedOperations []string // operationName values covered by enabled alerts
}

// AzureVM is the collected posture of an Azure virtual machine.
type AzureVM struct {
	Name             string
	ResourceGroup    string
	Subscription     string
	Location         string
	EncryptionAtHost bool // encryption at host enabled (protects temp/cache disks + VM-to-storage)
}

// AzureRedis is the collected posture of an Azure Cache for Redis instance.
type AzureRedis struct {
	Name              string
	ResourceGroup     string
	Subscription      string
	Location          string
	NonSSLPortEnabled bool // the non-TLS port (6379) is enabled
}

// AzureDBFlexServer is the collected posture of an Azure Database flexible
// server (MySQL or PostgreSQL).
type AzureDBFlexServer struct {
	Engine              string // "mysql" | "postgresql"
	Name                string
	ResourceGroup       string
	Subscription        string
	Location            string
	PublicNetworkAccess bool
}

// Azure is the collected Azure-side state for one or more subscriptions.
type Azure struct {
	StorageAccounts  []StorageAccount
	NSGs             []NetworkSecurityGroup
	KeyVaults        []KeyVault
	WebApps          []WebApp
	SQLServers       []SQLServer
	CosmosAccounts   []CosmosAccount
	DefenderPlans    []DefenderPlan
	CustomRoles      []AzureCustomRole
	AppRegistrations []AzureAppRegistration
	NICs             []AzureNIC
	SubnetNSGs       []AzureSubnetNSG
	Monitors         []AzureMonitor
	DBFlexServers    []AzureDBFlexServer
	VMs              []AzureVM
	RedisCaches      []AzureRedis
	SecretHits       []SecretHit
}

// --- GCP --------------------------------------------------------------------

// GCSBucket is the collected posture of a Cloud Storage bucket.
type GCSBucket struct {
	Name                     string
	Project                  string
	Location                 string
	PublicIAM                bool   // IAM policy grants allUsers / allAuthenticatedUsers
	UniformBucketLevelAccess bool   // uniform (vs legacy ACL) access enabled
	PublicAccessPrevention   string // "enforced" | "inherited"
}

// FirewallRule is the collected posture of a VPC firewall rule.
type FirewallRule struct {
	Name         string
	Project      string
	Network      string
	Direction    string // INGRESS | EGRESS
	Disabled     bool
	Allowed      []string // "tcp:22", "udp:53", "all"
	SourceRanges []string // e.g. "0.0.0.0/0"
}

// GCPIAMBinding is one role binding from a project's IAM policy.
type GCPIAMBinding struct {
	Project string
	Role    string   // e.g. roles/owner
	Members []string // e.g. allUsers, allAuthenticatedUsers, user:..., serviceAccount:...
}

// CloudSQLInstance is the collected posture of a Cloud SQL database instance.
type CloudSQLInstance struct {
	Name               string
	Project            string
	Region             string
	Version            string
	PublicIP           bool     // an IPv4 (public) address is enabled
	RequireSSL         bool     // connections must use SSL/TLS
	BackupEnabled      bool     // automated backups configured
	AuthorizedNetworks []string // CIDRs allowed to connect (0.0.0.0/0 = whole internet)
}

// OpenToInternet reports whether any authorized network spans the whole internet.
func (i CloudSQLInstance) OpenToInternet() bool {
	for _, n := range i.AuthorizedNetworks {
		if n == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

// ComputeInstance is the collected posture of a Compute Engine VM.
type ComputeInstance struct {
	Name              string
	Project           string
	Zone              string
	HasPublicIP       bool // a NIC has an external (NAT) IP
	ShieldedVM        bool // secure boot + vTPM + integrity monitoring all on
	DefaultSAFullAPI  bool // uses the default compute SA with the cloud-platform scope
	SerialPortEnabled bool // metadata serial-port-enable=true (interactive serial console)
	CanIPForward      bool // IP forwarding enabled (can act as a router)
}

// KMSCryptoKey is the collected posture of a Cloud KMS crypto key.
type KMSCryptoKey struct {
	Name            string
	Project         string
	Location        string
	KeyRing         string
	Purpose         string // e.g. ENCRYPT_DECRYPT
	RotationEnabled bool   // a rotation period is configured
	PublicIAM       bool   // IAM policy grants allUsers/allAuthenticatedUsers
}

// GKECluster is the collected posture of a GKE (Kubernetes Engine) cluster.
type GKECluster struct {
	Name                     string
	Project                  string
	Location                 string
	LegacyABAC               bool // legacy ABAC authorization enabled
	NetworkPolicyEnabled     bool // pod-level network policy enforcement on
	MasterAuthorizedNetworks bool // control-plane access restricted to allowed CIDRs
}

// GCPAuditLogging is a project's Cloud Audit Logging posture, derived from the
// allServices audit config on the project IAM policy.
type GCPAuditLogging struct {
	Project      string
	Collected    bool // the project IAM policy was read (so absence != "not logged" on a denied project)
	DataReadAll  bool // allServices DATA_READ logging enabled
	DataWriteAll bool // allServices DATA_WRITE logging enabled
}

// GCPLogMetric is a log-based metric and its filter, for CIS monitoring checks.
type GCPLogMetric struct {
	Name   string
	Filter string
}

// GCPMonitoring is a project's monitoring posture (CIS GCP section 2): its
// log-based metrics and the metric names referenced by alert policies.
type GCPMonitoring struct {
	Project            string
	ReadOK             bool // both the metrics and alert-policies reads succeeded
	Metrics            []GCPLogMetric
	AlertedMetricNames []string
}

// GCP is the collected GCP-side state for one or more projects.
type GCP struct {
	Buckets      []GCSBucket
	Firewalls    []FirewallRule
	IAMBindings  []GCPIAMBinding
	CloudSQL     []CloudSQLInstance
	ComputeVMs   []ComputeInstance
	KMSKeys      []KMSCryptoKey
	GKEClusters  []GKECluster
	AuditConfig  []GCPAuditLogging
	Monitoring   []GCPMonitoring
	WIFProviders []GCPWorkloadIdentityProvider
	SecretHits   []SecretHit
}

// GCPWorkloadIdentityProvider is one provider inside a workload-identity pool:
// an external identity source (an AWS account, an OIDC issuer such as Azure AD,
// or a SAML IdP) configured to federate into GCP and impersonate service
// accounts. It is the GCP side of cross-cloud federation.
type GCPWorkloadIdentityProvider struct {
	Project    string
	Pool       string // pool id (short)
	Provider   string // provider id (short)
	Kind       string // "aws" | "oidc" | "saml"
	AWSAccount string // AWS account id, for an aws provider
	Issuer     string // issuer URI, for an oidc provider
	Disabled   bool   // the provider or its pool is disabled/not active
}

// --- Kubernetes -------------------------------------------------------------

// K8sContainer is the collected security posture of one container in a pod.
type K8sContainer struct {
	Name                     string
	Image                    string // container image reference (for the Cepheus container inventory)
	Privileged               bool
	AllowPrivilegeEscalation bool // effective value (defaults true when unset, unless privileged)
	RunAsNonRoot             bool // effective value (container overrides pod)
}

// K8sPod is the collected security posture of a pod across one context.
type K8sPod struct {
	Name        string
	Namespace   string
	Context     string
	HostNetwork bool
	HostPID     bool
	HostIPC     bool
	Containers  []K8sContainer
}

// HostNamespaces reports whether the pod shares any host namespace.
func (p K8sPod) HostNamespaces() bool {
	return p.HostNetwork || p.HostPID || p.HostIPC
}

// K8sRole is a (Cluster)Role and whether its rules use dangerous wildcards.
type K8sRole struct {
	Name             string
	Namespace        string // empty for ClusterRole
	Context          string
	Kind             string // ClusterRole | Role
	WildcardVerb     bool   // a rule grants verb "*"
	WildcardResource bool   // a rule grants resource "*"
}

// RBACBinding is a (Cluster)RoleBinding: which role is bound to which subjects.
type RBACBinding struct {
	Name      string
	Namespace string // empty for ClusterRoleBinding
	Context   string
	Kind      string   // ClusterRoleBinding | RoleBinding
	RoleRef   string   // the referenced role name (e.g. cluster-admin)
	Subjects  []string // "Kind/name" e.g. "Group/system:authenticated"
}

// K8s is the collected Kubernetes-side state across one or more contexts.
type K8s struct {
	Pods       []K8sPod
	Roles      []K8sRole
	Bindings   []RBACBinding
	SecretHits []SecretHit
}

// State is the full collected state for a scan across providers.
type State struct {
	mu    sync.Mutex
	AWS   *AWS
	Azure *Azure
	GCP   *GCP
	K8s   *K8s
}

// New returns an initialized, empty State.
func New() *State {
	return &State{
		AWS: &AWS{
			EBSEncryptionByDefault:   map[string]bool{},
			ConfigByRegion:           map[string]ConfigStatus{},
			GuardDutyEnabledByRegion: map[string]bool{},
		},
		Azure: &Azure{},
		GCP:   &GCP{},
		K8s:   &K8s{},
	}
}

// AddK8sPod appends a collected pod under lock.
func (s *State) AddK8sPod(p K8sPod) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.K8s.Pods = append(s.K8s.Pods, p)
}

// AddK8sRole appends a collected (Cluster)Role under lock.
func (s *State) AddK8sRole(r K8sRole) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.K8s.Roles = append(s.K8s.Roles, r)
}

// AddRBACBinding appends a collected (Cluster)RoleBinding under lock.
func (s *State) AddRBACBinding(b RBACBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.K8s.Bindings = append(s.K8s.Bindings, b)
}

// AddGCSBucket appends a collected Cloud Storage bucket under lock.
func (s *State) AddGCSBucket(b GCSBucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.Buckets = append(s.GCP.Buckets, b)
}

// AddFirewallRule appends a collected VPC firewall rule under lock.
func (s *State) AddFirewallRule(r FirewallRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.Firewalls = append(s.GCP.Firewalls, r)
}

// AddK8sSecretHit appends a detected Kubernetes control-plane secret under lock.
func (s *State) AddK8sSecretHit(h SecretHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.K8s.SecretHits = append(s.K8s.SecretHits, h)
}

// AddCloudSQLInstance appends a collected Cloud SQL instance under lock.
func (s *State) AddCloudSQLInstance(i CloudSQLInstance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.CloudSQL = append(s.GCP.CloudSQL, i)
}

// AddComputeInstance appends a collected Compute Engine VM under lock.
func (s *State) AddComputeInstance(i ComputeInstance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.ComputeVMs = append(s.GCP.ComputeVMs, i)
}

// AddGCPMonitoring records a project's monitoring posture under lock.
func (s *State) AddGCPMonitoring(m GCPMonitoring) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.Monitoring = append(s.GCP.Monitoring, m)
}

// AddGCPAuditLogging records a project's audit-logging posture under lock.
func (s *State) AddGCPAuditLogging(a GCPAuditLogging) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.AuditConfig = append(s.GCP.AuditConfig, a)
}

// AddKMSCryptoKey appends a collected Cloud KMS key under lock.
func (s *State) AddKMSCryptoKey(k KMSCryptoKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.KMSKeys = append(s.GCP.KMSKeys, k)
}

// AddGKECluster appends a collected GKE cluster under lock.
func (s *State) AddGKECluster(c GKECluster) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.GKEClusters = append(s.GCP.GKEClusters, c)
}

// AddGCPSecretHit appends a detected GCP control-plane secret under lock.
func (s *State) AddGCPSecretHit(h SecretHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.SecretHits = append(s.GCP.SecretHits, h)
}

// AddGCPIAMBinding appends a collected project IAM binding under lock.
func (s *State) AddGCPIAMBinding(b GCPIAMBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.IAMBindings = append(s.GCP.IAMBindings, b)
}

// AddGCPWorkloadIdentityProvider appends a collected workload-identity provider.
func (s *State) AddGCPWorkloadIdentityProvider(p GCPWorkloadIdentityProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GCP.WIFProviders = append(s.GCP.WIFProviders, p)
}

// AddStorageAccount appends a collected Azure storage account under lock.
func (s *State) AddStorageAccount(a StorageAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.StorageAccounts = append(s.Azure.StorageAccounts, a)
}

// AddNSG appends a collected network security group under lock.
func (s *State) AddNSG(g NetworkSecurityGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.NSGs = append(s.Azure.NSGs, g)
}

// AddAzureNIC appends a collected network interface under lock.
func (s *State) AddAzureNIC(n AzureNIC) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.NICs = append(s.Azure.NICs, n)
}

// AddAzureSubnetNSG appends a collected subnet→NSG association under lock.
func (s *State) AddAzureSubnetNSG(n AzureSubnetNSG) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.SubnetNSGs = append(s.Azure.SubnetNSGs, n)
}

// AddKeyVault appends a collected key vault under lock.
func (s *State) AddKeyVault(v KeyVault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.KeyVaults = append(s.Azure.KeyVaults, v)
}

// AddAzureVM appends a collected virtual machine under lock.
func (s *State) AddAzureVM(v AzureVM) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.VMs = append(s.Azure.VMs, v)
}

// AddAzureRedis appends a collected Redis cache under lock.
func (s *State) AddAzureRedis(r AzureRedis) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.RedisCaches = append(s.Azure.RedisCaches, r)
}

// AddAzureDBFlexServer appends a collected MySQL/PostgreSQL flexible server under lock.
func (s *State) AddAzureDBFlexServer(d AzureDBFlexServer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.DBFlexServers = append(s.Azure.DBFlexServers, d)
}

// AddAzureMonitor appends a subscription's monitoring posture under lock.
func (s *State) AddAzureMonitor(m AzureMonitor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.Monitors = append(s.Azure.Monitors, m)
}

// AddAzureAppRegistration appends a collected Entra app registration under lock.
func (s *State) AddAzureAppRegistration(a AzureAppRegistration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.AppRegistrations = append(s.Azure.AppRegistrations, a)
}

// AddAzureCustomRole appends a collected custom RBAC role under lock.
func (s *State) AddAzureCustomRole(r AzureCustomRole) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.CustomRoles = append(s.Azure.CustomRoles, r)
}

// AddCosmosAccount appends a collected Cosmos DB account under lock.
func (s *State) AddCosmosAccount(a CosmosAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.CosmosAccounts = append(s.Azure.CosmosAccounts, a)
}

// AddDefenderPlan appends a collected Defender for Cloud plan under lock.
func (s *State) AddDefenderPlan(p DefenderPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.DefenderPlans = append(s.Azure.DefenderPlans, p)
}

// AddWebApp appends a collected Azure web app under lock.
func (s *State) AddWebApp(w WebApp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.WebApps = append(s.Azure.WebApps, w)
}

// AddSQLServer appends a collected Azure SQL server under lock.
func (s *State) AddSQLServer(srv SQLServer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.SQLServers = append(s.Azure.SQLServers, srv)
}

// AddAzureSecretHit appends a detected Azure control-plane secret under lock.
func (s *State) AddAzureSecretHit(h SecretHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.SecretHits = append(s.Azure.SecretHits, h)
}

// SetAWSAccount records the account id the AWS state belongs to.
func (s *State) SetAWSAccount(account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Account = account
}

// AddS3Bucket appends a collected bucket under lock.
func (s *State) AddS3Bucket(b S3Bucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.S3Buckets = append(s.AWS.S3Buckets, b)
}

// SetIAM stores the account-wide IAM posture under lock.
func (s *State) SetIAM(iam IAMState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	iam.Collected = true
	s.AWS.IAM = iam
}

// AddSecurityGroup appends a collected security group under lock.
func (s *State) AddSecurityGroup(g SecurityGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.SecurityGroups = append(s.AWS.SecurityGroups, g)
}

// AddInstance appends a collected EC2 instance under lock.
func (s *State) AddInstance(i EC2Instance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Instances = append(s.AWS.Instances, i)
}

// AddVolume appends a collected EBS volume under lock.
func (s *State) AddVolume(v EBSVolume) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Volumes = append(s.AWS.Volumes, v)
}

// AddSubnet appends a collected subnet under lock.
func (s *State) AddSubnet(sub Subnet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Subnets = append(s.AWS.Subnets, sub)
}

// AddRouteTable appends a collected route table under lock.
func (s *State) AddRouteTable(rt RouteTable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.RouteTables = append(s.AWS.RouteTables, rt)
}

// SetEBSDefaultEncryption records the per-region EBS default-encryption flag.
func (s *State) SetEBSDefaultEncryption(region string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.EBSEncryptionByDefault[region] = enabled
}

// AddRDSInstance appends a collected RDS instance under lock.
func (s *State) AddRDSInstance(r RDSInstance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.RDSInstances = append(s.AWS.RDSInstances, r)
}

// AddRedshiftCluster appends a collected Redshift cluster under lock.
func (s *State) AddRedshiftCluster(c RedshiftCluster) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Redshift = append(s.AWS.Redshift, c)
}

// AddECRRepository appends a collected ECR repository under lock.
func (s *State) AddECRRepository(r ECRRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.ECRRepos = append(s.AWS.ECRRepos, r)
}

// AddMessagingResource appends a collected SNS topic / SQS queue under lock.
func (s *State) AddMessagingResource(m MessagingResource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Messaging = append(s.AWS.Messaging, m)
}

// AddClassicELB appends a collected classic load balancer under lock.
func (s *State) AddClassicELB(e ClassicELB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.ClassicELBs = append(s.AWS.ClassicELBs, e)
}

// AddEFSFileSystem appends a collected EFS file system under lock.
func (s *State) AddEFSFileSystem(f EFSFileSystem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.EFS = append(s.AWS.EFS, f)
}

// AddElasticacheGroup appends a collected ElastiCache replication group under lock.
func (s *State) AddElasticacheGroup(g ElasticacheGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Elasticache = append(s.AWS.Elasticache, g)
}

// AddDynamoDBTable appends a collected DynamoDB table under lock.
func (s *State) AddDynamoDBTable(t DynamoDBTable) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.DynamoDB = append(s.AWS.DynamoDB, t)
}

// AddLogMetricFilter appends a collected CloudWatch Logs metric filter under lock.
func (s *State) AddLogMetricFilter(f LogMetricFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.LogMetricFilters = append(s.AWS.LogMetricFilters, f)
}

// AddAlarmedMetric records a CloudWatch metric name that has an alarm, under lock.
func (s *State) AddAlarmedMetric(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.AlarmedMetrics = append(s.AWS.AlarmedMetrics, name)
}

// AddLambdaFunction appends a collected Lambda function under lock.
func (s *State) AddLambdaFunction(f LambdaFunction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Lambdas = append(s.AWS.Lambdas, f)
}

// AddTrail appends a collected CloudTrail trail under lock.
func (s *State) AddTrail(t CloudTrailTrail) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Trails = append(s.AWS.Trails, t)
}

// AddKMSKey appends a collected KMS key under lock.
func (s *State) AddKMSKey(k KMSKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.KMSKeys = append(s.AWS.KMSKeys, k)
}

// SetConfigStatus records the AWS Config recorder status for a region.
func (s *State) SetConfigStatus(region string, status ConfigStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.ConfigByRegion[region] = status
}

// SetGuardDuty records whether a region has an enabled GuardDuty detector.
func (s *State) SetGuardDuty(region string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.GuardDutyEnabledByRegion[region] = enabled
}

// AddVPC appends a collected VPC (with its flow-log status) under lock.
func (s *State) AddVPC(v VPCInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.VPCs = append(s.AWS.VPCs, v)
}

// AddVPCPeering appends a collected VPC-peering connection under lock.
func (s *State) AddVPCPeering(p VPCPeering) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Peerings = append(s.AWS.Peerings, p)
}

// AddPublicEBSSnapshot records a publicly shared EBS snapshot under lock.
func (s *State) AddPublicEBSSnapshot(r ResourceRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.PublicEBSSnapshots = append(s.AWS.PublicEBSSnapshots, r)
}

// AddPublicAMI records a publicly shared AMI under lock.
func (s *State) AddPublicAMI(r ResourceRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.PublicAMIs = append(s.AWS.PublicAMIs, r)
}

// AddPublicRDSSnapshot records a publicly shared RDS snapshot under lock.
func (s *State) AddPublicRDSSnapshot(r ResourceRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.PublicRDSSnapshots = append(s.AWS.PublicRDSSnapshots, r)
}

// AddSecret appends a collected Secrets Manager secret under lock.
func (s *State) AddSecret(secret SecretInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Secrets = append(s.AWS.Secrets, secret)
}

// AddLoadBalancer appends a collected load balancer under lock.
func (s *State) AddLoadBalancer(lb LoadBalancer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.LoadBalancers = append(s.AWS.LoadBalancers, lb)
}

// AddCertificate appends a collected ACM certificate under lock.
func (s *State) AddCertificate(c Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Certificates = append(s.AWS.Certificates, c)
}

// AddRoute53Record appends a collected DNS record under lock.
func (s *State) AddRoute53Record(r Route53Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.Route53Records = append(s.AWS.Route53Records, r)
}

// AddSecretHit appends a detected control-plane secret under lock.
func (s *State) AddSecretHit(h SecretHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AWS.SecretHits = append(s.AWS.SecretHits, h)
}
