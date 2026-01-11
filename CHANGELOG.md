# Changelog

All notable changes to Nubicustos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Enhanced Scan Orchestration System
- **Docker SDK Integration**: Replaced subprocess-based shell script orchestration with direct Docker SDK calls for reliable container management
- **All AWS Tools Configured**: Added comprehensive tool configurations for all AWS security tools:
  - Prowler (v4.2.4) - AWS compliance and security scanning
  - ScoutSuite (v5.12.0) - Multi-cloud security auditing
  - CloudFox (v1.14.2) - AWS attack surface enumeration
  - CloudSploit - AWS security configuration scanning
  - Cloud Custodian (v0.9.34) - Policy-as-code enforcement
  - CloudMapper - AWS account visualization
  - Cartography (v0.94.0) - Asset relationship graphing to Neo4j
- **Expected Exit Codes**: Security tools now properly handle non-zero exit codes (1, 3) that indicate findings detected, not failures
- **Profile-Specific Options**: Scan profiles now support tool-specific command options:
  - Quick: Prowler with critical/high severity filter
  - Comprehensive: All 7 AWS tools with full scanning
  - Compliance-Only: Prowler + ScoutSuite with CIS, SOC2, PCI-DSS frameworks
- **Dynamic Profile Endpoint**: `/api/scans/profiles/list` now returns tool lists dynamically from configuration
- **Entrypoint Override Support**: Tools like CloudSploit that require custom entrypoints are now supported

### Changed
- **Tool Images Updated**: All Docker images now pinned to specific versions matching docker-compose.yml
- **Scan Orchestration Flow**: Sequential tool execution with proper completion detection and report processing
- **Profiles Endpoint**: Now returns comprehensive profile metadata including tools list and duration estimates

### Fixed
- **Exit Code Handling**: Security tools returning exit code 3 (Prowler with findings) no longer incorrectly marked as failed
- **Container Name Conflicts**: Unique execution IDs prevent container naming conflicts during concurrent scans

### Security
- Added security analysis documenting known considerations for Docker socket access and credential handling
- Input validation maintained for scan profiles and target parameters

---

## [1.0.1] - 2026-01-09

### Fixed
- Various bugs discovered during beta testing
- Improved stability across all scanning tools

---

## [1.0.0] - 2026-01-08

### Added

#### Core Platform
- Docker Compose orchestration for 20+ security scanning tools
- Multi-cloud support for AWS, Azure, GCP, and OCI
- Kubernetes security scanning capabilities
- Infrastructure-as-Code security analysis
- PostgreSQL database for centralized findings storage
- Neo4j graph database for asset relationship mapping
- Grafana dashboards for security posture visualization
- REST API (FastAPI) for programmatic access
- Nginx web server for report viewing

#### Cloud Security Tools
- **AWS**: Prowler, ScoutSuite, Pacu, CloudSploit, Cloud Custodian, Cartography
- **Azure**: ScoutSuite, CloudSploit, Cloud Custodian
- **GCP**: Prowler, ScoutSuite, CloudSploit, Cartography
- **OCI**: CloudSploit

#### Kubernetes Security Tools
- kube-bench for CIS Kubernetes Benchmark
- Kubescape for NSA, MITRE ATT&CK, and CIS frameworks
- kube-hunter for penetration testing
- kube-linter for static analysis
- Polaris for best practices validation
- Trivy for container vulnerability scanning
- Grype for container image analysis
- Popeye for resource analysis
- Falco for runtime threat detection

#### IaC Security Tools
- Checkov for Terraform, CloudFormation, Kubernetes, Helm, ARM
- Terrascan for policy-as-code enforcement
- tfsec for Terraform security scanning

#### Scan Management
- Scan profiles: quick, comprehensive, compliance-only
- Severity filtering for targeted scanning
- Dry-run mode for command preview
- JSON output for automation
- Scan comparison with MTTR metrics

#### Update System
- `scripts/update.sh` for comprehensive stack updates
- Tool image version tracking in `data/versions.json`
- Category-based update filtering (aws, kubernetes, iac, infrastructure)
- Rollback capability for tools and stack
- Health validation after updates

#### Permission Validation
- `scripts/check-permissions.py` for pre-flight credential validation
- Support for AWS, Azure, GCP, and Kubernetes
- Remediation instructions for missing permissions
- CLI credential overrides

#### Export and Reporting
- Multiple report formats: HTML, JSON, CSV
- REST API endpoints for data export
- Historical tracking in PostgreSQL
- Asset visualization in Neo4j

### Security
- Credential isolation via Docker volume mounts
- Network segmentation with Docker networks
- API key authentication support
- Gitignore for sensitive directories

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.1 | 2026-01-09 | Bug fixes from beta testing |
| 1.0.0 | 2026-01-08 | Initial release |

---

## Upgrade Notes

### Upgrading to 1.0.1
No breaking changes. Simply run:
```bash
git pull origin main
docker-compose pull
docker-compose up -d
```

---

[Unreleased]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Su1ph3r/Nubicustos/releases/tag/v1.0.0
