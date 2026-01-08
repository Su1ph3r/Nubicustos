# Changelog

All notable changes to Argus will be documented in this file.

## [1.1.0] - 2026-01-08

### Added

#### Update System
- New `scripts/update.sh` - Comprehensive update manager for the entire stack
- New `scripts/update-lib.sh` - Helper library with tool mappings and version tracking
- New `data/` directory for version state tracking
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
- New `scripts/check-permissions.py` - Pre-flight permission validation tool
- New `scripts/permission_requirements.py` - Permission definitions for all tools
- Validates AWS, Azure, GCP, and Kubernetes credentials before scanning
- Provides remediation instructions for missing permissions

### Changed

#### Rebranding: Cloud Security Audit Stack -> Argus
- Renamed project to "Argus" (after the hundred-eyed giant of Greek mythology)
- Renamed GitHub repository from `Cloud-Stack` to `Argus`
- Updated all file headers, help text, and documentation
- New repository URL: https://github.com/Su1ph3r/Argus

#### Files Updated for Rebranding
- `README.md` - New title, architecture diagram, clone instructions
- `CLAUDE.md` - Project overview
- `STRUCTURE.md` - Directory structure documentation
- `CHEATSHEET.md` - Command reference
- `.gitignore` - Header comment
- `.env.example` - Header comment
- `init.sql` - Database schema header
- `api/main.py` - API title and descriptions
- `scripts/run-all-audits.sh` - Headers and banners
- `scripts/export-findings.sh` - Header
- `scripts/profile-loader.sh` - Header

### Documentation
- Added `data/` to key directories list
- Created this `CHANGELOG.md`

---

## [1.0.0] - Previous

Initial release of Cloud Security Audit Stack with:
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
