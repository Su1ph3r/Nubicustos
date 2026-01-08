# Changelog

All notable changes to Nubicustos will be documented in this file.

## [1.0.0] - 2026-01-08

### Initial Release

Nubicustos - Cloud Security Platform

#### Core Features
- 20+ security scanning tools orchestration
- Multi-cloud support (AWS, Azure, GCP, OCI)
- Kubernetes security scanning
- Infrastructure-as-Code scanning
- PostgreSQL findings database
- Neo4j asset graph
- Grafana dashboards
- REST API
- Scan profiles (quick, comprehensive, compliance-only)
- Report export functionality

#### Update System
- `scripts/update.sh` - Comprehensive update manager for the entire stack
- `scripts/update-lib.sh` - Helper library with tool mappings and version tracking
- `data/` directory for version state tracking
- Commands:
  - `./scripts/update.sh all` - Update everything (git + images + custom builds)
  - `./scripts/update.sh pull [tools...]` - Pull external Docker images
  - `./scripts/update.sh build` - Rebuild custom images (api, cloudmapper)
  - `./scripts/update.sh self` - Update stack from git repository
  - `./scripts/update.sh versions` - Display installed versions of all tools
  - `./scripts/update.sh rollback <tool|stack>` - Revert to previous version
- Options: `--category`, `--dry-run`, `--no-health-check`, `--force`
- Health validation after updates
- Rollback capability via stored image digests
- Version tracking in `data/versions.json`

#### Permission Validator
- `scripts/check-permissions.py` - Pre-flight permission validation tool
- `scripts/permission_requirements.py` - Permission definitions for all tools
- Validates AWS, Azure, GCP, and Kubernetes credentials before scanning
- Provides remediation instructions for missing permissions
