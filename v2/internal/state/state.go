// Package state holds the normalized cloud configuration that collectors gather
// and checks evaluate. It is the in-memory boundary between the "read the cloud"
// phase (providers) and the "judge the cloud" phase (checks), so neither side
// has to know about the other.
//
// Collectors run concurrently, so all mutating accessors are mutex-guarded.
package state

import (
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

// IngressRule is a single inbound security-group rule.
type IngressRule struct {
	Protocol string // tcp, udp, icmp, -1 (all)
	FromPort int
	ToPort   int
	OpenV4   bool // contains 0.0.0.0/0
	OpenV6   bool // contains ::/0
}

// SecurityGroup is the collected ingress posture of a security group.
type SecurityGroup struct {
	ID      string
	Name    string
	Region  string
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
}

// EBSVolume is the collected encryption posture of a volume.
type EBSVolume struct {
	ID        string
	Region    string
	Encrypted bool
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

	RDSInstances []RDSInstance
	Trails       []CloudTrailTrail

	KMSKeys                  []KMSKey
	ConfigByRegion           map[string]ConfigStatus // region -> recorder status
	GuardDutyEnabledByRegion map[string]bool         // region -> has an enabled detector

	VPCs               []VPCInfo
	PublicEBSSnapshots []ResourceRef
	PublicAMIs         []ResourceRef
	PublicRDSSnapshots []ResourceRef

	Secrets       []SecretInfo
	LoadBalancers []LoadBalancer
	Certificates  []Certificate
}

// --- Azure ------------------------------------------------------------------

// StorageAccount is the collected posture of an Azure storage account.
type StorageAccount struct {
	Name                  string
	ResourceGroup         string
	Subscription          string
	Location              string
	AllowBlobPublicAccess bool   // account permits anonymous blob/container access
	HTTPSOnly             bool   // EnableHTTPSTrafficOnly
	MinTLSVersion         string // e.g. "TLS1_2"
	NetworkDefaultAllow   bool   // network rule set default action == Allow (open to all networks)
}

// NSGRule is a single inbound/outbound security rule on a network security group.
type NSGRule struct {
	Name      string
	Direction string // Inbound | Outbound
	Access    string // Allow | Deny
	Protocol  string // Tcp | Udp | * ...
	Priority  int
	DestPorts string // destination port or range (e.g. "22", "0-65535", "*")
	Source    string // source prefix: "*", "Internet", "0.0.0.0/0", a CIDR
}

// OpenToInternet reports whether the rule allows inbound traffic from the whole
// internet (source "*", "Internet", or a 0.0.0.0/0 ::/0 prefix on an Allow rule).
func (r NSGRule) OpenToInternet() bool {
	if !strings.EqualFold(r.Direction, "Inbound") || !strings.EqualFold(r.Access, "Allow") {
		return false
	}
	switch r.Source {
	case "*", "Internet", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

// NetworkSecurityGroup is the collected rule posture of an Azure NSG.
type NetworkSecurityGroup struct {
	Name          string
	ResourceGroup string
	Subscription  string
	Location      string
	Rules         []NSGRule
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

// Azure is the collected Azure-side state for one or more subscriptions.
type Azure struct {
	StorageAccounts []StorageAccount
	NSGs            []NetworkSecurityGroup
	KeyVaults       []KeyVault
}

// State is the full collected state for a scan across providers.
type State struct {
	mu    sync.Mutex
	AWS   *AWS
	Azure *Azure
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
	}
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

// AddKeyVault appends a collected key vault under lock.
func (s *State) AddKeyVault(v KeyVault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Azure.KeyVaults = append(s.Azure.KeyVaults, v)
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
