# Changelog

All notable changes to Nubicustos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.0.5] - 2026-04-04

### Added

#### Audit Logging
- `api/services/audit_service.py` — Structured audit trail for administrative actions (database purge, settings changes)
- `AuditHistory` model with action, details, and timestamp fields
- `GET /api/settings/audit-log` endpoint for retrieving audit history

#### Background Task Registry
- `api/services/task_registry.py` — Centralized tracking for background tasks (scans, sync, analysis)
- `GET /api/health/tasks` endpoint listing active background tasks
- Enhanced health endpoint with scheduler and background task status

#### Report Processor Modularization
- `report-processor/parsers/` — Extracted parser modules: `cloud_parsers.py`, `iac_parsers.py`, `iam_parsers.py`, `secrets_parsers.py`, `utils.py`
- `report-processor/db_writer.py` — Extracted database writer with dead-letter queue for failed processing
- `process_reports.py` reduced from 3,346 to 530 lines via modular extraction

#### Test Suites
- `nubicustos-mcp/tests/` — MCP contract tests (68 tests) covering all tools, client methods, and error handling
- `report-processor/tests/` — Report processor tests (14 tests) for parsers and database writes
- `frontend/src/__tests__/api-contract.spec.js` — Frontend API contract tests (30 tests)
- `api/tests/test_audit.py` — Audit logging tests
- `api/tests/test_settings.py` — Settings endpoint tests

#### Export Enhancements
- `tool` query parameter on `/api/exports/csv` and `/api/exports/json` endpoints for tool-filtered exports
- Export summary now includes both "open" and "fail" status findings for accurate counts
- `/api/exports/generate` download URL now preserves filter parameters

#### Blast Radius Improvements
- `skipped_identities` count in blast radius responses when identity analysis fails
- Mutually exclusive risk level bucketing (critical/high/medium/low no longer double-count overlapping capabilities)

#### Scheduler Reliability
- Schedules auto-disable after 5 consecutive execution failures with warning log
- Schedule create/update endpoints now verify job scheduling succeeded; disable with warning if not

### Fixed

#### Critical
- **Scan status stuck in "running"**: `_update_scan_status` no longer swallows exceptions silently; re-raises after logging so callers can handle the failure
- **MCP `verify_credentials` always returned 400**: Client now passes provider-specific credential sub-objects to the API
- **MCP `run_enumerate_iam` always returned 400**: Client now sends `access_key`/`secret_key` instead of the non-existent `principal_arn` field
- **Report processing failure hidden**: Scans now carry error metadata when report processing fails instead of showing "Completed — 0 findings"

#### Security
- **SSRF in report-processor notifications**: Added `_validate_webhook_url()` with hostname resolution and private IP rejection
- **DNS rebinding bypass in webhook validation**: Added `SSRFSafeAdapter` that validates resolved IPs at connect time, eliminating the TOCTOU gap
- **Command injection in PoC commands**: Resource IDs now shell-quoted with `shlex.quote()` in generated CLI commands
- SSRF validation on both Slack and Teams webhook URLs in report-processor

#### Data Integrity
- `risk_score` and `cvss_score` of 0.0 no longer exported as `null` (was treated as falsy)
- `mark_stale_assets` now respects the `hours` parameter instead of marking all missing assets as stale immediately
- `tool_sources` JSON field properly validated as list type to prevent substring matching bugs
- `FINDING_INSERT_MAP` key corrected from `exploitability` to `exploitation_likelihood`
- Neo4j partial sync now correctly reports `success = False` when label sync fails
- Audit log entry after database purge is now committed to the database
- Background sync task creates its own DB session instead of using the request-scoped session that may be closed

#### Error Handling
- Blast radius identity analysis failures logged with ARN context instead of silently dropped
- ScoutSuite resource extraction failures logged instead of silently swallowed
- `_get_validation_settings` handles non-string values (int, None, bool) without crashing on `.lower()`
- `cloudtrail_lookback_hours` setting parsing handles non-numeric strings gracefully
- Settings query failures logged at WARNING level instead of invisible DEBUG
- Database rollback failures now logged instead of silently swallowed
- Notification error strings include exception type name for diagnostics
- IMDS STS identity failures logged at WARNING before defaulting to "unknown"
- `fetchSummary` in findings store now shows toast notification on error (consistent with other store actions)
- `send_slack_notification` narrowed from bare `except Exception` to specific `HTTPError`/`RequestException`
- `findings.py` trend endpoint handles both date objects and SQLite string returns

#### Pagination
- Validation history double-offset fixed — Python-level slice only applied for combined queries, not when DB already applied offset
- Odd `limit` values in combined validation history queries no longer silently lose one entry

#### Other
- CISA KEV cache handles missing or empty `cached_at` timestamps without crashing
- Empty ARN segments from trailing colons no longer produce invalid CLI commands
- Removed dead `getExecutionsHealthSummary` frontend method (endpoint never existed)
- Health check table counts use ORM queries instead of raw SQL

### Changed
- Pydantic schemas use strict mode when `STRICT_MODE=true` is set, rejecting unknown fields
- Default password warnings logged at startup when using default database credentials
- Webhook URL validation requires HTTPS scheme and rejects private/loopback/link-local IPs
- Version bumped to 1.0.5 across API, frontend, and MCP server

---

## [1.0.4] - 2026-02-09

### Added

#### Cross-Tool Integration
- `GET /exports/containers` endpoint exporting container inventory in Cepheus-compatible format
- `export_source: "nubicustos"` field added to JSON exports for downstream tool identification
- NULL `resource_id` deduplication fix with `finding-{id}` fallback

---

## [1.0.3] - 2026-01-18

### Added

#### Phase 1: Open Source Features

##### Intelligent Alert Prioritization
- Enhanced risk scoring with asset criticality multipliers (critical: 1.3x, high: 1.15x, medium: 1.0x, low: 0.85x)
- Blast radius scoring for downstream impact assessment (1-100+ resources)
- Recurrence penalty for repeat findings (up to 1.2x multiplier)
- New API endpoint: `GET /api/findings/top-critical` - Returns highest-risk findings by score
- New API endpoint: `GET /api/findings/trend` - Returns severity trend over time for dashboard charts
- New database columns: `asset_criticality`, `blast_radius`, `recurrence_count`, `scoring_factors`

##### Threat Intelligence Enrichment (Design Framework)
- Extensible provider framework for threat intelligence integrations
- `ThreatIntelProvider` abstract base class for implementing providers
- `ThreatIntelResult` dataclass for standardized enrichment results
- `ProviderRegistry` for managing multiple providers
- `PlaceholderProvider` implementation demonstrating design pattern
- New API endpoint: `GET /api/findings/{id}/threat-intel` - Returns enrichment data structure
- Indicator extraction from findings (IP addresses, domains, hashes)
- Future provider support: AlienVault OTX, VirusTotal, Shodan, GreyNoise, AbuseIPDB

##### Scheduled Scanning
- APScheduler integration for recurring security scans
- Support for cron expressions (5-field standard: minute hour day month day_of_week)
- Support for interval-based schedules (minimum 5 minutes)
- New API endpoints:
  - `GET /api/schedules` - List all schedules
  - `POST /api/schedules` - Create schedule
  - `GET /api/schedules/{id}` - Get schedule details
  - `PATCH /api/schedules/{id}` - Update schedule
  - `DELETE /api/schedules/{id}` - Delete schedule
  - `POST /api/schedules/{id}/trigger` - Trigger immediate execution
  - `GET /api/schedules/status` - Get scheduler status and job list
- New database table: `scan_schedules` with full audit trail
- Automatic schedule loading on API startup
- Non-fatal scheduler failures (API continues if scheduler fails)

##### Slack/Teams Notifications
- Scan completion notifications with findings summary
- Slack webhook integration with formatted messages
- Microsoft Teams webhook integration with adaptive card format
- Unified notification dispatcher supporting multiple channels
- Configuration via Settings API:
  - `PUT /api/settings/notifications_enabled`
  - `PUT /api/settings/slack_webhook_url`
  - `PUT /api/settings/teams_webhook_url`
- Non-fatal notification failures (scan completes even if notification fails)

##### Enhanced Dashboard
- New API endpoint: `GET /api/executions/health/summary` - Tool execution health statistics
- New Vue component: `RiskTrendChart.vue` - Bar chart showing severity trend over time
- New Vue component: `ToolHealthCard.vue` - Grid displaying tool execution health with success rates
- New Vue component: `ComplianceOverview.vue` - Framework compliance cards with percentages
- Dashboard sections for risk trends and tool health monitoring

#### Utilities
- Docker cleanup utility (`scripts/cleanup.sh`) for managing containers, images, and volumes
  - Interactive menu mode for guided cleanup
  - CLI flags: `--containers`, `--images`, `--images-local`, `--volumes`, `--prune`, `--all`
  - Safety features: `--dry-run` preview mode, confirmation prompts, `--force` for automation
  - Warnings before destructive operations (volume deletion)

### Changed
- Dashboard view extended with health and compliance grid sections
- Findings router extended with new endpoint routes (ordered before `/{finding_id}` to avoid conflicts)
- Main application lifespan includes scheduler lifecycle management

### Fixed
- Database session leak in scheduler service (proper try/finally cleanup)
- Private IP detection using `ipaddress` module for accurate RFC 1918 compliance

### Documentation
- Added `docs/PHASE1_FEATURES.md` with comprehensive feature documentation
- API endpoint documentation for all new routes
- Database migration instructions

---

## [1.0.2] - 2025-01-14

### Security
- Fixed path traversal vulnerability with `os.path.realpath()` validation
- Added zip slip prevention in archive creation with arcname validation
- Fixed ReDoS vulnerability with input length limits
- Added log sanitization to redact credentials, tokens, and IP addresses
- Limited validation error details to prevent schema disclosure
- Added specific SQLAlchemyError handling to prevent information leakage
- Added security analysis documenting known considerations for Docker socket access and credential handling
- Input validation maintained for scan profiles and target parameters

### Added

#### Bulk Operations
- Bulk scan operations: multi-select, bulk delete, and bulk archive
- New `scan_files` database table tracking report files per scan
- Archive service for creating downloadable zip files of scan reports
- API endpoints: `DELETE /scans/bulk`, `POST /scans/bulk/archive`, `GET /scans/archives`

#### Error Handling & Observability
- Per-tool error tracking with detailed error breakdown
- New endpoint: `GET /scans/{scan_id}/errors` for error analysis
- Centralized toast notification service in frontend
- Error dialog in ScansView with per-tool status display
- Safe error message extraction to prevent information leakage

#### Operational Features
- Orphan scan recovery on API startup
- Dynamic AWS profile support with `aws_profile` field in scan creation
- Assumed role analysis endpoint (`POST /api/assumed-roles/analyze`) and UI
- Expected exit codes handling: security tools returning 1 or 3 no longer incorrectly marked as failed
- On-demand Docker image building for security tools
- IMDS scan credentials support for EC2/ECS environments

#### Security Analysis Features
- Privilege escalation path analyzer for IAM policy analysis
- Attack path analysis feature for penetration testing
- MCP server for LLM integration and enhanced scan/compliance features

#### UI Enhancements
- Compliance detail view with framework breakdown
- Tool execution monitoring in scan details
- Vue.js frontend with enhanced findings display and PoC evidence

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
- **Profile-Specific Options**: Scan profiles now support tool-specific command options:
  - Quick: Prowler with critical/high severity filter
  - Comprehensive: All 7 AWS tools with full scanning
  - Compliance-Only: Prowler + ScoutSuite with CIS, SOC2, PCI-DSS frameworks
- **Dynamic Profile Endpoint**: `/api/scans/profiles/list` now returns tool lists dynamically from configuration
- **Entrypoint Override Support**: Tools like CloudSploit that require custom entrypoints are now supported

#### Build & Testing
- Multi-stage Docker build for frontend (no manual build required)
- Integration tests for scan pipeline (`api/tests/test_report_processing.py`)
- Smoke test script (`scripts/smoke_test.sh`)

### Fixed
- Docker network detection now works with any project directory name
- HOST_PROJECT_PATH defaulting to empty string issue
- Docker network name mismatch preventing scan launches
- Report processing for findings population
- Button spacing in Assumed Role Mapper view
- Prowler compliance framework (corrected to `pci_3.2.1_aws`)
- Removed broken ScoutSuite ruleset option
- Exit code handling: security tools returning exit code 3 (Prowler with findings) no longer incorrectly marked as failed
- Container name conflicts: unique execution IDs prevent container naming conflicts during concurrent scans
- Credentials mount to allow saving profiles
- Docker Compose profiles for improved startup reliability
- ESLint configuration for Vue/PrimeVue patterns

### Changed
- Improved error handling with meaningful user-facing messages
- Frontend build moved to Docker container (multi-stage build)
- Report processor dependencies added to API container
- CloudMapper Dockerfile updated to Python 3.9
- Tool images updated: All Docker images now pinned to specific versions matching docker-compose.yml
- Scan orchestration flow: Sequential tool execution with proper completion detection and report processing
- Profiles endpoint: Now returns comprehensive profile metadata including tools list and duration estimates
- Comprehensive documentation added for new features

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
| 1.0.5 | 2026-04-04 | Security hardening, 80 bug fixes, audit logging, report processor modularization, test suites |
| 1.0.4 | 2026-02-09 | Cross-tool integration: container export endpoint, export_source field |
| 1.0.3 | 2026-01-18 | Phase 1 Open Source features: alert prioritization, threat intel, scheduling, notifications, dashboard |
| 1.0.2 | 2025-01-14 | Security fixes, bulk operations, error handling improvements |
| 1.0.1 | 2026-01-09 | Bug fixes from beta testing |
| 1.0.0 | 2026-01-08 | Initial release |

---

## Upgrade Notes

### Upgrading to 1.0.5
No breaking changes. No database migration required. Rebuild and restart:
```bash
git pull origin main
docker compose build api && docker compose up -d api
```

### Upgrading to 1.0.3
No breaking changes. Apply database migration and rebuild:
```bash
git pull origin main
docker exec -i postgresql psql -U auditor -d security_audits < db-migrations/001_phase1_features.sql
docker compose build api && docker compose up -d api
```

### Upgrading to 1.0.2
No breaking changes. Run:
```bash
git pull origin main
docker compose build api
docker compose up -d
```

### Upgrading to 1.0.1
No breaking changes. Simply run:
```bash
git pull origin main
docker-compose pull
docker-compose up -d
```

---

[Unreleased]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.5...HEAD
[1.0.5]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Su1ph3r/Nubicustos/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Su1ph3r/Nubicustos/releases/tag/v1.0.0
