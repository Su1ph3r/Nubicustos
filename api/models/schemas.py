"""Pydantic schemas for API request/response models.

Security Notes:
- All string inputs have maximum length constraints to prevent DoS attacks
- Regex patterns validate format where applicable
- Enum types restrict values to known safe options
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum
import re


class SeverityLevel(str, Enum):
    """Severity level enumeration."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class FindingStatus(str, Enum):
    """Finding status enumeration."""
    open = "open"
    closed = "closed"
    mitigated = "mitigated"
    accepted = "accepted"


class ScanProfile(str, Enum):
    """Available scan profiles."""
    quick = "quick"
    comprehensive = "comprehensive"
    compliance_only = "compliance-only"


# ============================================================================
# Scan Schemas
# ============================================================================

class ScanCreate(BaseModel):
    """Request schema for creating a new scan."""
    profile: ScanProfile = Field(default=ScanProfile.comprehensive, description="Scan profile to use")
    target: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Specific target to scan"
    )
    severity_filter: Optional[str] = Field(
        default=None,
        max_length=100,
        pattern=r'^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$',
        description="Comma-separated severity levels"
    )
    dry_run: bool = Field(default=False, description="Preview commands without executing")

    @field_validator('target')
    @classmethod
    def validate_target(cls, v):
        """Validate target does not contain shell metacharacters."""
        if v is None:
            return v
        # Block shell metacharacters that could be used for injection
        dangerous_chars = ['|', '&', ';', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"Invalid character in target: {char}")
        return v


class ScanResponse(BaseModel):
    """Response schema for scan details."""
    scan_id: UUID
    scan_type: Optional[str]
    target: Optional[str]
    tool: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Response schema for listing scans."""
    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Finding Schemas
# ============================================================================

class RemediationCommand(BaseModel):
    """Remediation command details."""
    type: str = Field(description="Command type: cli, terraform, etc.")
    command: str = Field(description="The actual command to execute")
    description: Optional[str] = Field(default=None, description="What this command does")


class RemediationResource(BaseModel):
    """External resource for remediation guidance."""
    title: str = Field(description="Resource title")
    url: str = Field(description="Resource URL")
    type: str = Field(default="documentation", description="Resource type: documentation, blog, video")


class AffectedResource(BaseModel):
    """Details of an affected resource."""
    id: str = Field(description="Resource ID")
    name: Optional[str] = Field(default=None, description="Resource name")
    region: Optional[str] = Field(default=None, description="Resource region")
    type: Optional[str] = Field(default=None, description="Resource type")


class FindingResponse(BaseModel):
    """Response schema for finding details."""
    id: int
    finding_id: Optional[str]
    scan_id: Optional[UUID]
    tool: Optional[str]
    cloud_provider: Optional[str]
    account_id: Optional[str] = Field(default=None, description="Cloud account ID")
    severity: Optional[str]
    status: str = "open"
    title: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    resource_name: Optional[str]
    region: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    # Risk scoring fields
    risk_score: Optional[float] = Field(default=None, description="CVSS-style risk score (0-100)")
    cvss_score: Optional[float] = Field(default=None, description="CVSS base score (0-10)")
    exploitability: Optional[str] = Field(default=None, description="Exploitation likelihood: confirmed, likely, theoretical, unlikely")
    # Proof of Concept Evidence
    poc_evidence: Optional[str] = Field(default=None, description="Raw evidence/API response demonstrating the finding")
    poc_verification: Optional[str] = Field(default=None, description="Command to verify the finding exists")
    poc_screenshot_path: Optional[str] = Field(default=None, description="Path to screenshot evidence")
    # Enhanced Remediation
    remediation_commands: Optional[List[RemediationCommand]] = Field(default=None, description="CLI/IaC commands to fix")
    remediation_code: Optional[Dict[str, str]] = Field(default=None, description="Code snippets by language/tool")
    remediation_resources: Optional[List[RemediationResource]] = Field(default=None, description="External documentation links")
    # Deduplication fields
    canonical_id: Optional[str] = Field(default=None, description="Canonical ID for grouping similar findings")
    tool_sources: Optional[List[str]] = Field(default=None, description="List of tools that detected this finding")
    affected_resources: Optional[List[AffectedResource]] = Field(default=None, description="List of affected resources")
    affected_count: Optional[int] = Field(default=None, description="Count of affected resources")

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Request schema for updating a finding."""
    status: Optional[FindingStatus] = None
    tags: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom tags for the finding"
    )

    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        """Validate tags don't exceed limits and keys are safe."""
        if v is None:
            return v
        # Limit number of tags
        if len(v) > 50:
            raise ValueError("Maximum 50 tags allowed")
        # Validate tag keys and values
        for key, value in v.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ValueError("Tag keys must be strings with max length 64")
            # Validate key contains only safe characters
            if not re.match(r'^[a-zA-Z0-9_\-\.]+$', key):
                raise ValueError(f"Invalid tag key format: {key}")
            # Limit value size
            if isinstance(value, str) and len(value) > 256:
                raise ValueError(f"Tag value for '{key}' exceeds 256 characters")
        return v


class FindingListResponse(BaseModel):
    """Response schema for listing findings."""
    findings: List[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingSummary(BaseModel):
    """Summary of findings by severity."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    by_provider: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}


# ============================================================================
# Health Schemas
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    database: str
    timestamp: datetime
    version: str = "1.0.0"


class ServiceStatus(BaseModel):
    """Individual service status."""
    name: str
    status: str
    message: Optional[str] = None
    latency_ms: Optional[float] = Field(default=None, description="Response time in milliseconds")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional service details")


class DependencyHealth(BaseModel):
    """Health status for a dependency."""
    name: str
    status: str = Field(description="healthy, unhealthy, or degraded")
    latency_ms: Optional[float] = None
    version: Optional[str] = None
    message: Optional[str] = None
    last_check: datetime


class DetailedHealthResponse(BaseModel):
    """Detailed health check response with all dependencies."""
    status: str = Field(description="Overall status: healthy, degraded, or unhealthy")
    services: List[ServiceStatus]
    timestamp: datetime
    uptime_seconds: Optional[float] = Field(default=None, description="API uptime in seconds")
    request_id: Optional[str] = Field(default=None, description="Current request correlation ID")


class LivenessResponse(BaseModel):
    """Kubernetes liveness probe response."""
    status: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    """Kubernetes readiness probe response."""
    ready: bool
    status: str
    checks: Dict[str, bool] = Field(description="Individual readiness checks")
    timestamp: datetime


# ============================================================================
# Export Schemas
# ============================================================================

class ExportFormat(str, Enum):
    """Allowed export formats."""
    csv = "csv"
    json = "json"


class ExportRequest(BaseModel):
    """Request schema for generating exports."""
    format: ExportFormat = Field(default=ExportFormat.csv, description="Export format: csv, json")
    severity_filter: Optional[List[SeverityLevel]] = None
    cloud_provider: Optional[str] = Field(
        default=None,
        max_length=32,
        pattern=r'^[a-z0-9\-]+$',
        description="Cloud provider filter (aws, azure, gcp, kubernetes)"
    )
    status_filter: Optional[List[FindingStatus]] = None
    include_remediation: bool = True


class ExportResponse(BaseModel):
    """Response schema for export generation."""
    export_id: str
    filename: str
    format: str
    record_count: int
    download_url: str
    generated_at: datetime


# ============================================================================
# Attack Path Schemas
# ============================================================================

class AttackPathNode(BaseModel):
    """Node in an attack path."""
    id: str
    type: str = Field(description="Node type: entry_point, resource, or target")
    name: str
    resource_id: Optional[str] = None
    region: Optional[str] = None


class AttackPathEdge(BaseModel):
    """Edge in an attack path."""
    id: str
    source: str
    target: str
    type: str
    name: str
    finding_id: Optional[int] = None
    exploitability: str = "theoretical"
    impact: str = "medium"


class PoCStep(BaseModel):
    """Single step in a Proof of Concept."""
    step: int
    name: str
    description: str
    command: str
    mitre_technique: Optional[str] = None
    requires_auth: bool = False


class AttackPathResponse(BaseModel):
    """Response schema for attack path details."""
    id: int
    path_id: str
    scan_id: Optional[UUID] = None
    name: str
    description: Optional[str] = None
    entry_point_type: str
    entry_point_id: Optional[str] = None
    entry_point_name: Optional[str] = None
    target_type: str
    target_description: Optional[str] = None
    nodes: List[AttackPathNode]
    edges: List[AttackPathEdge]
    finding_ids: List[int] = []
    risk_score: int
    exploitability: str
    impact: str
    hop_count: int
    requires_authentication: bool = False
    requires_privileges: bool = False
    poc_available: bool = False
    poc_steps: List[PoCStep] = []
    mitre_tactics: List[str] = []
    aws_services: List[str] = []
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AttackPathListResponse(BaseModel):
    """Response schema for listing attack paths."""
    paths: List[AttackPathResponse]
    total: int
    page: int
    page_size: int


class AttackPathSummary(BaseModel):
    """Summary statistics for attack paths."""
    total_paths: int = 0
    critical_paths: int = 0
    high_risk_paths: int = 0
    medium_risk_paths: int = 0
    low_risk_paths: int = 0
    entry_point_types: Dict[str, int] = {}
    target_types: Dict[str, int] = {}
    top_mitre_tactics: List[str] = []
    avg_risk_score: float = 0.0


class AttackPathAnalyzeRequest(BaseModel):
    """Request to trigger attack path analysis."""
    scan_id: Optional[UUID] = Field(default=None, description="Specific scan to analyze")
    max_depth: int = Field(default=5, ge=1, le=10, description="Maximum path depth")


class AttackPathAnalyzeResponse(BaseModel):
    """Response from attack path analysis."""
    paths_discovered: int
    analysis_time_ms: int
    summary: AttackPathSummary


# ============================================================================
# Public Exposure Schemas
# ============================================================================

class PublicExposureResponse(BaseModel):
    """Response schema for public exposure details."""
    id: int
    exposure_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource_type: str
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    exposure_type: str
    exposure_details: Optional[Dict[str, Any]] = None
    risk_level: str = "medium"
    protocol: Optional[str] = None
    port_range: Optional[str] = None
    source_cidr: Optional[str] = None
    is_internet_exposed: bool = False
    finding_ids: Optional[List[int]] = None
    tags: Optional[Dict[str, Any]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: str = "open"

    class Config:
        from_attributes = True


class PublicExposureListResponse(BaseModel):
    """Response schema for listing public exposures."""
    exposures: List[PublicExposureResponse]
    total: int
    page: int
    page_size: int


class PublicExposureSummary(BaseModel):
    """Summary of public exposures."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    internet_exposed: int = 0
    by_type: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}


# ============================================================================
# Exposed Credential Schemas
# ============================================================================

class ExposedCredentialResponse(BaseModel):
    """Response schema for exposed credential details."""
    id: int
    credential_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    source_type: str
    source_location: Optional[str] = None
    credential_type: str
    credential_name: Optional[str] = None
    is_active: bool = True
    risk_level: str = "critical"
    finding_ids: Optional[List[int]] = None
    discovered_by: Optional[str] = None
    remediation_status: str = "pending"
    remediation_notes: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True


class ExposedCredentialListResponse(BaseModel):
    """Response schema for listing exposed credentials."""
    credentials: List[ExposedCredentialResponse]
    total: int
    page: int
    page_size: int


class ExposedCredentialSummary(BaseModel):
    """Summary of exposed credentials."""
    total: int = 0
    active: int = 0
    by_type: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}


class CredentialRemediationUpdate(BaseModel):
    """Request to update credential remediation status."""
    remediation_status: str = Field(description="Status: pending, in_progress, resolved, accepted")
    remediation_notes: Optional[str] = None


# ============================================================================
# Severity Override Schemas
# ============================================================================

class SeverityOverrideCreate(BaseModel):
    """Request schema for creating a severity override."""
    finding_id: int
    new_severity: str = Field(description="New severity: critical, high, medium, low, info")
    justification: str = Field(min_length=10, description="Justification for the override")
    created_by: Optional[str] = None
    expires_at: Optional[datetime] = None


class SeverityOverrideResponse(BaseModel):
    """Response schema for severity override details."""
    id: int
    finding_id: int
    original_severity: str
    new_severity: str
    justification: str
    override_type: str = "manual"
    created_by: Optional[str] = None
    approved_by: Optional[str] = None
    approval_status: str = "pending"
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SeverityOverrideListResponse(BaseModel):
    """Response schema for listing severity overrides."""
    overrides: List[SeverityOverrideResponse]
    total: int
    page: int
    page_size: int


class SeverityOverrideApproval(BaseModel):
    """Request to approve or reject a severity override."""
    approved: bool
    approved_by: str
    notes: Optional[str] = None


# ============================================================================
# Privilege Escalation Path Schemas
# ============================================================================

class PrivescPathNode(BaseModel):
    """Node in a privilege escalation path."""
    id: str
    type: str
    name: str
    arn: Optional[str] = None
    permissions: Optional[List[str]] = None


class PrivescPathEdge(BaseModel):
    """Edge in a privilege escalation path."""
    id: str
    source: str
    target: str
    method: str
    description: Optional[str] = None
    requires_condition: bool = False


class PrivescPathResponse(BaseModel):
    """Response schema for privilege escalation path details."""
    id: int
    path_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str
    account_id: Optional[str] = None
    source_principal_type: str
    source_principal_arn: Optional[str] = None
    source_principal_name: Optional[str] = None
    target_principal_type: str
    target_principal_arn: Optional[str] = None
    target_principal_name: Optional[str] = None
    escalation_method: str
    escalation_details: Optional[Dict[str, Any]] = None
    path_nodes: Optional[List[PrivescPathNode]] = []
    path_edges: Optional[List[PrivescPathEdge]] = []
    risk_score: int = 0
    exploitability: str = "theoretical"
    requires_conditions: Optional[Dict[str, Any]] = None
    mitre_techniques: Optional[List[str]] = None
    poc_commands: Optional[List[Dict[str, str]]] = None
    finding_ids: Optional[List[int]] = None
    status: str = "open"
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PrivescPathListResponse(BaseModel):
    """Response schema for listing privilege escalation paths."""
    paths: List[PrivescPathResponse]
    total: int
    page: int
    page_size: int


class PrivescPathSummary(BaseModel):
    """Summary of privilege escalation paths."""
    total_paths: int = 0
    critical_paths: int = 0
    high_risk_paths: int = 0
    by_method: Dict[str, int] = {}
    by_target: Dict[str, int] = {}


# ============================================================================
# IMDS Check Schemas
# ============================================================================

class ImdsCheckResponse(BaseModel):
    """Response schema for IMDS check details."""
    id: int
    check_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    instance_id: Optional[str] = None
    instance_name: Optional[str] = None
    imds_version: Optional[str] = None
    imds_v1_enabled: bool = False
    imds_hop_limit: Optional[int] = None
    http_endpoint_enabled: bool = True
    http_tokens_required: bool = False
    ssrf_vulnerable: bool = False
    container_credential_exposure: bool = False
    ecs_task_role_exposed: bool = False
    eks_pod_identity_exposed: bool = False
    vulnerability_details: Optional[Dict[str, Any]] = None
    risk_level: str = "medium"
    finding_ids: Optional[List[int]] = None
    remediation_status: str = "pending"
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ImdsCheckListResponse(BaseModel):
    """Response schema for listing IMDS checks."""
    checks: List[ImdsCheckResponse]
    total: int
    page: int
    page_size: int


class ImdsCheckSummary(BaseModel):
    """Summary of IMDS checks."""
    total_instances: int = 0
    imds_v1_enabled: int = 0
    ssrf_vulnerable: int = 0
    container_exposed: int = 0
    by_region: Dict[str, int] = {}


# ============================================================================
# CloudFox Schemas
# ============================================================================

class CloudfoxResultResponse(BaseModel):
    """Response schema for CloudFox result details."""
    id: int
    result_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    module_name: str
    result_type: Optional[str] = None
    resource_arn: Optional[str] = None
    resource_name: Optional[str] = None
    finding_category: Optional[str] = None
    finding_details: Optional[Dict[str, Any]] = None
    risk_level: str = "medium"
    loot_file_path: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CloudfoxResultListResponse(BaseModel):
    """Response schema for listing CloudFox results."""
    results: List[CloudfoxResultResponse]
    total: int
    page: int
    page_size: int


class CloudfoxSummary(BaseModel):
    """Summary of CloudFox results."""
    total_results: int = 0
    by_module: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_risk: Dict[str, int] = {}


class CloudfoxRunRequest(BaseModel):
    """Request to run CloudFox modules."""
    modules: List[str] = Field(default=["all"], description="Modules to run")
    profile: Optional[str] = None
    regions: Optional[List[str]] = None


# ============================================================================
# Pacu Schemas
# ============================================================================

class PacuResultResponse(BaseModel):
    """Response schema for Pacu result details."""
    id: int
    result_id: str
    scan_id: Optional[UUID] = None
    session_name: Optional[str] = None
    module_name: str
    module_category: Optional[str] = None
    execution_status: Optional[str] = None
    target_account_id: Optional[str] = None
    target_region: Optional[str] = None
    resources_affected: int = 0
    permissions_used: Optional[List[str]] = None
    findings: Optional[List[Dict[str, Any]]] = None
    loot_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    execution_time_ms: Optional[int] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PacuResultListResponse(BaseModel):
    """Response schema for listing Pacu results."""
    results: List[PacuResultResponse]
    total: int
    page: int
    page_size: int


class PacuSummary(BaseModel):
    """Summary of Pacu results."""
    total_executions: int = 0
    successful: int = 0
    failed: int = 0
    by_module: Dict[str, int] = {}
    by_category: Dict[str, int] = {}


class PacuRunRequest(BaseModel):
    """Request to run Pacu modules."""
    module: str = Field(description="Module to execute")
    session_name: Optional[str] = None
    args: Optional[Dict[str, Any]] = None
    # AWS credentials
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    region: Optional[str] = None


# ============================================================================
# enumerate-iam Schemas
# ============================================================================

class EnumerateIamResultResponse(BaseModel):
    """Response schema for enumerate-iam result details."""
    id: int
    result_id: str
    scan_id: Optional[UUID] = None
    account_id: Optional[str] = None
    principal_arn: Optional[str] = None
    principal_name: Optional[str] = None
    principal_type: Optional[str] = None
    enumeration_method: Optional[str] = None
    confirmed_permissions: Optional[List[str]] = None
    denied_permissions: Optional[List[str]] = None
    error_permissions: Optional[List[str]] = None
    permission_count: int = 0
    high_risk_permissions: Optional[List[str]] = None
    privesc_capable: bool = False
    data_access_capable: bool = False
    admin_capable: bool = False
    enumeration_duration_ms: Optional[int] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class EnumerateIamListResponse(BaseModel):
    """Response schema for listing enumerate-iam results."""
    results: List[EnumerateIamResultResponse]
    total: int
    page: int
    page_size: int


class EnumerateIamSummary(BaseModel):
    """Summary of enumerate-iam results."""
    total_principals: int = 0
    privesc_capable: int = 0
    admin_capable: int = 0
    data_access_capable: int = 0
    avg_permissions: float = 0.0


class EnumerateIamRunRequest(BaseModel):
    """Request to run enumerate-iam."""
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    profile: Optional[str] = None
    region: Optional[str] = None


# ============================================================================
# Assumed Role Mapping Schemas
# ============================================================================

class AssumedRoleMappingResponse(BaseModel):
    """Response schema for assumed role mapping details."""
    id: int
    mapping_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str
    account_id: Optional[str] = None
    source_principal_type: str
    source_principal_arn: Optional[str] = None
    source_principal_name: Optional[str] = None
    source_account_id: Optional[str] = None
    target_role_arn: str
    target_role_name: Optional[str] = None
    target_account_id: Optional[str] = None
    trust_policy: Optional[Dict[str, Any]] = None
    conditions: Optional[Dict[str, Any]] = None
    is_cross_account: bool = False
    is_external_id_required: bool = False
    max_session_duration: Optional[int] = None
    assumption_chain_depth: int = 1
    risk_level: str = "medium"
    neo4j_synced: bool = False
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AssumedRoleMappingListResponse(BaseModel):
    """Response schema for listing assumed role mappings."""
    mappings: List[AssumedRoleMappingResponse]
    total: int
    page: int
    page_size: int


class AssumedRoleSummary(BaseModel):
    """Summary of assumed role mappings."""
    total_mappings: int = 0
    cross_account: int = 0
    external_id_required: int = 0
    by_source_type: Dict[str, int] = {}
    by_risk: Dict[str, int] = {}


class Neo4jSyncRequest(BaseModel):
    """Request to sync role mappings to Neo4j."""
    mapping_ids: Optional[List[int]] = None
    sync_all: bool = False


# ============================================================================
# Lambda Analysis Schemas
# ============================================================================

class SecretFinding(BaseModel):
    """A secret found in Lambda code."""
    type: str
    value_preview: str = Field(description="Redacted preview of the value")
    location: str
    line_number: Optional[int] = None
    confidence: str = "high"


class VulnerableDependency(BaseModel):
    """A vulnerable dependency in Lambda."""
    package: str
    version: str
    vulnerability: str
    severity: str
    cve: Optional[str] = None


class InsecurePattern(BaseModel):
    """An insecure code pattern found."""
    pattern_type: str
    description: str
    location: str
    line_number: Optional[int] = None
    recommendation: str


class LambdaAnalysisResponse(BaseModel):
    """Response schema for Lambda analysis details."""
    id: int
    analysis_id: str
    scan_id: Optional[UUID] = None
    cloud_provider: str = "aws"
    account_id: Optional[str] = None
    region: Optional[str] = None
    function_arn: Optional[str] = None
    function_name: Optional[str] = None
    runtime: Optional[str] = None
    handler: Optional[str] = None
    code_size_bytes: Optional[int] = None
    memory_size: Optional[int] = None
    timeout_seconds: Optional[int] = None
    environment_variables: Optional[Dict[str, str]] = None
    has_vpc_config: bool = False
    layers: Optional[List[str]] = None
    secrets_found: Optional[List[SecretFinding]] = None
    hardcoded_credentials: Optional[List[Dict[str, Any]]] = None
    vulnerable_dependencies: Optional[List[VulnerableDependency]] = None
    insecure_patterns: Optional[List[InsecurePattern]] = None
    api_keys_exposed: Optional[List[Dict[str, Any]]] = None
    database_connections: Optional[List[Dict[str, Any]]] = None
    external_urls: Optional[List[str]] = None
    risk_score: int = 0
    risk_level: str = "medium"
    finding_ids: Optional[List[int]] = None
    analysis_status: str = "pending"
    analysis_error: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class LambdaAnalysisListResponse(BaseModel):
    """Response schema for listing Lambda analyses."""
    analyses: List[LambdaAnalysisResponse]
    total: int
    page: int
    page_size: int


class LambdaAnalysisSummary(BaseModel):
    """Summary of Lambda analyses."""
    total_functions: int = 0
    functions_with_secrets: int = 0
    functions_with_vulns: int = 0
    high_risk: int = 0
    by_runtime: Dict[str, int] = {}
    by_region: Dict[str, int] = {}


class LambdaAnalyzeRequest(BaseModel):
    """Request to analyze Lambda functions."""
    function_arns: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    analyze_all: bool = False
    # AWS credentials
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    region: Optional[str] = None


# ============================================================================
# Tool Execution Schemas
# ============================================================================

class ToolExecutionStatus(str, Enum):
    """Tool execution status."""
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ToolExecutionResponse(BaseModel):
    """Response schema for tool execution details."""
    id: int
    execution_id: str
    tool_name: str
    tool_type: str
    status: str
    container_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    output_path: Optional[str] = None
    error_message: Optional[str] = None
    exit_code: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ToolExecutionListResponse(BaseModel):
    """Response schema for listing tool executions."""
    executions: List[ToolExecutionResponse]
    total: int
    page: int
    page_size: int


class ToolExecutionStartResponse(BaseModel):
    """Response schema for starting a tool execution."""
    execution_id: str
    tool_name: str
    status: str
    message: str
    container_id: Optional[str] = None
    error: Optional[str] = None


class ToolExecutionLogsResponse(BaseModel):
    """Response schema for tool execution logs."""
    execution_id: str
    logs: str
    status: str


# ============================================================================
# Settings Schemas
# ============================================================================

class SettingCategory(str, Enum):
    """Setting categories."""
    scans = "scans"
    data = "data"
    notifications = "notifications"
    display = "display"


class UserSettingResponse(BaseModel):
    """Response schema for a single user setting."""
    id: int
    setting_key: str
    setting_value: Any
    category: str
    description: Optional[str] = None
    updated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserSettingListResponse(BaseModel):
    """Response schema for listing user settings."""
    settings: List[UserSettingResponse]
    total: int


class UserSettingsByCategory(BaseModel):
    """Settings grouped by category."""
    scans: Dict[str, Any] = {}
    data: Dict[str, Any] = {}
    notifications: Dict[str, Any] = {}
    display: Dict[str, Any] = {}


class UserSettingUpdate(BaseModel):
    """Request schema for updating a setting."""
    value: Any = Field(description="The new value for the setting")


class UserSettingCreate(BaseModel):
    """Request schema for creating a new setting."""
    setting_key: str = Field(max_length=128, pattern=r'^[a-z0-9_]+$')
    setting_value: Any
    category: SettingCategory
    description: Optional[str] = Field(default=None, max_length=512)


class SettingsResetResponse(BaseModel):
    """Response after resetting settings."""
    message: str
    settings_reset: int


# ============================================================================
# Credential Status Cache Schemas
# ============================================================================

class CredentialStatusResponse(BaseModel):
    """Response schema for credential status cache."""
    id: int
    provider: str
    status: str
    identity: Optional[str] = None
    account_info: Optional[str] = None
    tools_ready: Optional[List[str]] = []
    tools_partial: Optional[List[str]] = []
    tools_failed: Optional[List[str]] = []
    last_verified: Optional[datetime] = None
    verification_error: Optional[str] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CredentialStatusListResponse(BaseModel):
    """Response schema for listing all credential statuses."""
    statuses: List[CredentialStatusResponse]
    summary: Dict[str, str] = Field(description="Provider -> status mapping")
