// Package state holds the normalized cloud configuration that collectors gather
// and checks evaluate. It is the in-memory boundary between the "read the cloud"
// phase (providers) and the "judge the cloud" phase (checks), so neither side
// has to know about the other.
//
// Collectors run concurrently, so all mutating accessors are mutex-guarded.
package state

import (
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

// EC2Instance is the collected posture of an instance.
type EC2Instance struct {
	ID             string
	Region         string
	PublicIP       string
	IMDSv2Required bool
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

// State is the full collected state for a scan across providers.
type State struct {
	mu  sync.Mutex
	AWS *AWS
}

// New returns an initialized, empty State.
func New() *State {
	return &State{AWS: &AWS{
		EBSEncryptionByDefault:   map[string]bool{},
		ConfigByRegion:           map[string]ConfigStatus{},
		GuardDutyEnabledByRegion: map[string]bool{},
	}}
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
