#!/usr/bin/env python3
"""
Process and merge ScoutSuite and Prowler reports into a unified format.

ReportProcessor is a thin orchestrator that delegates parsing to the
``parsers`` package and database operations to ``db_writer``.
"""

import logging
import os
import re
from datetime import datetime
from pathlib import Path

from parsers import (
    process_checkov_report as _process_checkov_report,
    process_cloudsplaining_report as _process_cloudsplaining_report,
    process_cloudsploit_report as _process_cloudsploit_report,
    process_gitleaks_report as _process_gitleaks_report,
    process_kube_linter_report as _process_kube_linter_report,
    process_pmapper_report as _process_pmapper_report,
    process_polaris_report as _process_polaris_report,
    process_prowler_report as _process_prowler_report,
    process_scoutsuite_report as _process_scoutsuite_report,
    process_terrascan_report as _process_terrascan_report,
    process_tfsec_report as _process_tfsec_report,
    process_trufflehog_report as _process_trufflehog_report,
)
from db_writer import (
    connect_db as _connect_db,
    generate_unified_report as _generate_unified_report,
    register_scan_files as _register_scan_files,
    retry_dead_letters as _retry_dead_letters,
    save_to_database as _save_to_database,
)

# Re-export strip_html_tags at module level for backwards compatibility
from parsers.utils import strip_html_tags  # noqa: F401

# Import attack validation modules (optional - graceful degradation if unavailable)
try:
    from blast_radius_analyzer import BlastRadiusAnalyzer
except ImportError:
    BlastRadiusAnalyzer = None

try:
    from poc_validator import PoCValidator
except ImportError:
    PoCValidator = None

try:
    from runtime_correlator import RuntimeCorrelator
except ImportError:
    RuntimeCorrelator = None


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ReportProcessor:
    # Keep class-level constants for backward compatibility with any external code
    # that references ReportProcessor.GENERIC_RESOURCE_NAMES, etc.
    from parsers.utils import (
        GENERIC_RESOURCE_NAMES,
        AWS_RESOURCE_ID_PATTERN,
        SERVICE_NORMALIZATION,
        CHECK_ID_PATTERNS,
    )

    def __init__(self):
        # Require explicit password - no insecure defaults
        db_password = os.environ.get("DB_PASSWORD")
        if not db_password:
            logger.warning("DB_PASSWORD not set, using environment default")
            db_password = os.environ.get("POSTGRES_PASSWORD", "")

        self.db_config = {
            "host": os.environ.get("DB_HOST", "postgresql"),
            "database": os.environ.get("DB_NAME", "security_audits"),
            "user": os.environ.get("DB_USER", "auditor"),
            "password": db_password,
        }
        self.reports_dir = Path("/reports")
        self.processed_dir = Path("/processed")
        self.processed_dir.mkdir(exist_ok=True)
        # Store account_id discovered from any tool for cross-reference
        self._discovered_account_id = None

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def connect_db(self):
        return _connect_db(self.db_config)

    def save_to_database(self, metadata, findings, scan_id, existing_scan_id=None):
        return _save_to_database(self.db_config, metadata, findings, scan_id, existing_scan_id)

    def _get_db_connection(self):
        """Get a database connection for validation features. Returns conn or None."""
        return self.connect_db()

    def generate_unified_report(self):
        return _generate_unified_report(self.db_config, self.processed_dir)

    def _register_scan_files(self, scan_id: str, tool: str, file_paths: list):
        return _register_scan_files(self.db_config, scan_id, tool, file_paths)

    # ------------------------------------------------------------------
    # Parser delegations
    # ------------------------------------------------------------------

    def process_scoutsuite_report(self, report_path):
        metadata, findings, new_account_id = _process_scoutsuite_report(
            report_path, self._discovered_account_id
        )
        if new_account_id:
            self._discovered_account_id = new_account_id
        return metadata, findings

    def process_prowler_report(self, report_path):
        metadata, findings, new_account_id = _process_prowler_report(
            report_path, self._discovered_account_id
        )
        if new_account_id:
            self._discovered_account_id = new_account_id
        return metadata, findings

    def process_cloudsploit_report(self, report_path):
        return _process_cloudsploit_report(report_path, self._discovered_account_id)

    def process_kube_linter_report(self, report_path):
        return _process_kube_linter_report(report_path)

    def process_polaris_report(self, report_path):
        return _process_polaris_report(report_path)

    def process_checkov_report(self, report_path):
        return _process_checkov_report(report_path)

    def process_terrascan_report(self, report_path):
        return _process_terrascan_report(report_path)

    def process_tfsec_report(self, report_path):
        return _process_tfsec_report(report_path)

    def process_trufflehog_report(self, report_path):
        return _process_trufflehog_report(report_path, self._discovered_account_id)

    def process_gitleaks_report(self, report_path):
        return _process_gitleaks_report(report_path, self._discovered_account_id)

    def process_pmapper_report(self, report_path):
        return _process_pmapper_report(report_path, self._discovered_account_id)

    def process_cloudsplaining_report(self, report_path):
        return _process_cloudsplaining_report(report_path, self._discovered_account_id)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def _log_directory_contents(self, tool_name: str) -> None:
        """Log directory contents for debugging report discovery issues."""
        tool_dir = self.reports_dir / tool_name
        try:
            if not tool_dir.exists():
                logger.warning(f"  Directory does not exist: {tool_dir}")
                return
            if not tool_dir.is_dir():
                logger.warning(f"  Path exists but is not a directory: {tool_dir}")
                return

            try:
                contents = list(tool_dir.iterdir())
            except PermissionError:
                logger.error(f"  Permission denied reading directory: {tool_dir}")
                logger.error("  On Linux, run: sudo chmod -R 755 ./reports")
                return

            if not contents:
                logger.warning(f"  Directory is empty: {tool_dir}")
                return

            logger.info(f"  Directory contents of {tool_dir}:")
            for item in contents[:10]:
                try:
                    stat_info = item.stat()
                    mode = oct(stat_info.st_mode)[-3:]
                    logger.info(f"    {item.name} (mode: {mode})")
                except PermissionError:
                    logger.warning(f"    {item.name} (permission denied)")
            if len(contents) > 10:
                logger.info(f"    ... and {len(contents) - 10} more items")

        except Exception as e:
            logger.error(f"  Error listing directory {tool_dir}: {e}")

    def process_for_scan(self, orchestration_scan_id: str, tools: list = None):
        """Process reports and link findings to an existing orchestration scan.

        This method is called by the scan orchestration after tools complete.
        It processes only reports generated by the specified tools and links
        all findings to the orchestration's scan_id.

        Args:
            orchestration_scan_id: UUID of the existing scan record from orchestration
            tools: Optional list of tools to process (e.g., ['prowler', 'scoutsuite'])
                  If None, processes all available reports.

        Returns:
            int: Total number of findings processed
        """
        logger.info(f"Processing reports for orchestration scan: {orchestration_scan_id}")
        logger.info(f"Reports directory: {self.reports_dir}")
        logger.info(f"Reports directory exists: {self.reports_dir.exists()}")

        # Check reports directory accessibility
        if not self.reports_dir.exists():
            logger.error(f"Reports directory does not exist: {self.reports_dir}")
            return 0
        try:
            list(self.reports_dir.iterdir())
        except PermissionError:
            logger.error(f"Permission denied accessing reports directory: {self.reports_dir}")
            logger.error("On Linux, run: sudo chmod -R 755 ./reports")
            return 0

        total_findings = 0
        processed_files = {}  # tool -> list of file paths

        # Process each tool's reports
        tools_to_process = tools or [
            "prowler", "scoutsuite", "cloudsploit", "cloudfox",
            "trufflehog", "gitleaks", "pmapper", "cloudsplaining"
        ]
        logger.info(f"Tools to process: {tools_to_process}")

        if "prowler" in tools_to_process:
            prowler_reports = list(self.reports_dir.glob("prowler/*/prowler-output-*.json"))
            prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.json"))
            prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.ocsf.json"))
            prowler_reports = list(set(prowler_reports))
            logger.info(f"Found {len(prowler_reports)} Prowler report(s)")
            if prowler_reports:
                prowler_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = prowler_reports[0]
                logger.info(f"Processing Prowler report: {report}")
                metadata, findings = self.process_prowler_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"prowler_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["prowler"] = [str(report)]
                else:
                    logger.warning(f"Prowler report yielded no findings: {report}")
            else:
                logger.warning("No Prowler reports found. Checking directory contents...")
                self._log_directory_contents("prowler")

        if "prowler-azure" in tools_to_process:
            prowler_azure_reports = list(self.reports_dir.glob("prowler-azure/*/prowler-output-*.json"))
            prowler_azure_reports += list(self.reports_dir.glob("prowler-azure/prowler-output-*.json"))
            prowler_azure_reports += list(self.reports_dir.glob("prowler-azure/prowler-output-*.ocsf.json"))
            prowler_azure_reports = list(set(prowler_azure_reports))
            logger.info(f"Found {len(prowler_azure_reports)} Prowler Azure report(s)")
            if prowler_azure_reports:
                prowler_azure_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = prowler_azure_reports[0]
                logger.info(f"Processing Prowler Azure report: {report}")
                metadata, findings = self.process_prowler_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"prowler_azure_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["prowler-azure"] = [str(report)]
                else:
                    logger.warning(f"Prowler Azure report yielded no findings: {report}")
            else:
                logger.warning("No Prowler Azure reports found. Checking directory contents...")
                self._log_directory_contents("prowler-azure")

        if "scoutsuite" in tools_to_process:
            scoutsuite_reports = list(
                self.reports_dir.glob("scoutsuite/*/scoutsuite-results/scoutsuite_results*.js")
            )
            scoutsuite_reports += list(
                self.reports_dir.glob("scoutsuite/*/scoutsuite_results_*.json")
            )
            scoutsuite_reports = list(set(scoutsuite_reports))
            logger.info(f"Found {len(scoutsuite_reports)} ScoutSuite report(s)")
            if scoutsuite_reports:
                scoutsuite_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = scoutsuite_reports[0]
                logger.info(f"Processing ScoutSuite report: {report}")
                metadata, findings = self.process_scoutsuite_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"scoutsuite_{report.parent.name}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["scoutsuite"] = [str(report)]
                else:
                    logger.warning(f"ScoutSuite report yielded no findings: {report}")
            else:
                logger.warning("No ScoutSuite reports found. Checking directory contents...")
                self._log_directory_contents("scoutsuite")

        if "scoutsuite-azure" in tools_to_process:
            scoutsuite_azure_reports = list(
                self.reports_dir.glob("scoutsuite/azure/scoutsuite-results/scoutsuite_results*.js")
            )
            scoutsuite_azure_reports += list(
                self.reports_dir.glob("scoutsuite/azure/scoutsuite_results_*.json")
            )
            scoutsuite_azure_reports = list(set(scoutsuite_azure_reports))
            logger.info(f"Found {len(scoutsuite_azure_reports)} ScoutSuite Azure report(s)")
            if scoutsuite_azure_reports:
                scoutsuite_azure_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = scoutsuite_azure_reports[0]
                logger.info(f"Processing ScoutSuite Azure report: {report}")
                metadata, findings = self.process_scoutsuite_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"scoutsuite_azure_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["scoutsuite-azure"] = [str(report)]
                else:
                    logger.warning(f"ScoutSuite Azure report yielded no findings: {report}")
            else:
                logger.warning("No ScoutSuite Azure reports found.")

        if "cloudsploit" in tools_to_process:
            cloudsploit_reports = list(self.reports_dir.glob("cloudsploit/*.json"))
            logger.info(f"Found {len(cloudsploit_reports)} CloudSploit report(s)")
            if cloudsploit_reports:
                cloudsploit_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = cloudsploit_reports[0]
                logger.info(f"Processing CloudSploit report: {report}")
                metadata, findings = self.process_cloudsploit_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"cloudsploit_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["cloudsploit"] = [str(report)]
                else:
                    logger.warning(f"CloudSploit report yielded no findings: {report}")
            else:
                logger.warning("No CloudSploit reports found. Checking directory contents...")
                self._log_directory_contents("cloudsploit")

        if "cloudfox" in tools_to_process:
            cloudfox_output_dir = self.reports_dir / "cloudfox" / "cloudfox-output"
            if cloudfox_output_dir.exists():
                json_files = list(cloudfox_output_dir.glob("**/*.json"))
                if json_files:
                    logger.info(
                        f"CloudFox: Found {len(json_files)} enumeration files (stored in cloudfox_results table)"
                    )
                    processed_files["cloudfox"] = [str(f) for f in json_files]

        # ========================================================================
        # IaC Security Tools
        # ========================================================================

        if "checkov" in tools_to_process:
            checkov_reports = list(self.reports_dir.glob("checkov/*.json"))
            checkov_reports += list(self.reports_dir.glob("checkov/results*.json"))
            checkov_reports = list(set(checkov_reports))
            if checkov_reports:
                checkov_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = checkov_reports[0]
                logger.info(f"Processing Checkov report: {report}")
                metadata, findings = self.process_checkov_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"checkov_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["checkov"] = [str(report)]

        if "terrascan" in tools_to_process:
            terrascan_reports = list(self.reports_dir.glob("terrascan/*.json"))
            terrascan_reports += list(self.reports_dir.glob("terrascan/terrascan-results*.json"))
            terrascan_reports = list(set(terrascan_reports))
            if terrascan_reports:
                terrascan_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = terrascan_reports[0]
                logger.info(f"Processing Terrascan report: {report}")
                metadata, findings = self.process_terrascan_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"terrascan_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["terrascan"] = [str(report)]

        if "tfsec" in tools_to_process:
            tfsec_reports = list(self.reports_dir.glob("tfsec/*.json"))
            tfsec_reports += list(self.reports_dir.glob("tfsec/tfsec-*.json"))
            tfsec_reports = list(set(tfsec_reports))
            if tfsec_reports:
                tfsec_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = tfsec_reports[0]
                logger.info(f"Processing tfsec report: {report}")
                metadata, findings = self.process_tfsec_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"tfsec_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["tfsec"] = [str(report)]

        if "kube-linter" in tools_to_process:
            kube_linter_reports = list(self.reports_dir.glob("kube-linter/*.json"))
            if kube_linter_reports:
                kube_linter_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = kube_linter_reports[0]
                logger.info(f"Processing kube-linter report: {report}")
                metadata, findings = self.process_kube_linter_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"kube_linter_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["kube-linter"] = [str(report)]

        if "polaris" in tools_to_process:
            polaris_reports = list(self.reports_dir.glob("polaris/*.json"))
            polaris_reports += list(self.reports_dir.glob("polaris/polaris-*.json"))
            polaris_reports = list(set(polaris_reports))
            if polaris_reports:
                polaris_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = polaris_reports[0]
                logger.info(f"Processing Polaris report: {report}")
                metadata, findings = self.process_polaris_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"polaris_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["polaris"] = [str(report)]

        # ========================================================================
        # Secrets Scanning Tools
        # ========================================================================

        if "trufflehog" in tools_to_process:
            trufflehog_reports = list(self.reports_dir.glob("trufflehog/*.json"))
            trufflehog_reports += list(self.reports_dir.glob("trufflehog/results.json"))
            trufflehog_reports = list(set(trufflehog_reports))
            if trufflehog_reports:
                trufflehog_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = trufflehog_reports[0]
                logger.info(f"Processing TruffleHog report: {report}")
                metadata, findings = self.process_trufflehog_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"trufflehog_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["trufflehog"] = [str(report)]

        if "gitleaks" in tools_to_process:
            gitleaks_reports = list(self.reports_dir.glob("gitleaks/*.json"))
            gitleaks_reports += list(self.reports_dir.glob("gitleaks/results.json"))
            gitleaks_reports = list(set(gitleaks_reports))
            if gitleaks_reports:
                gitleaks_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = gitleaks_reports[0]
                logger.info(f"Processing Gitleaks report: {report}")
                metadata, findings = self.process_gitleaks_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"gitleaks_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["gitleaks"] = [str(report)]

        # ========================================================================
        # IAM Deep Analysis Tools
        # ========================================================================

        if "pmapper" in tools_to_process:
            pmapper_reports = list(self.reports_dir.glob("pmapper/*.json"))
            pmapper_reports += list(self.reports_dir.glob("pmapper/privesc-*.json"))
            pmapper_reports = list(set(pmapper_reports))
            if pmapper_reports:
                pmapper_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = pmapper_reports[0]
                logger.info(f"Processing PMapper report: {report}")
                metadata, findings = self.process_pmapper_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"pmapper_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["pmapper"] = [str(report)]

        if "cloudsplaining" in tools_to_process:
            cloudsplaining_reports = list(self.reports_dir.glob("cloudsplaining/*.json"))
            cloudsplaining_reports += list(self.reports_dir.glob("cloudsplaining/*-iam-results.json"))
            cloudsplaining_reports = list(set(cloudsplaining_reports))
            if cloudsplaining_reports:
                cloudsplaining_reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                report = cloudsplaining_reports[0]
                logger.info(f"Processing Cloudsplaining report: {report}")
                metadata, findings = self.process_cloudsplaining_report(report)
                if metadata and findings:
                    self.save_to_database(
                        metadata,
                        findings,
                        f"cloudsplaining_{report.stem}",
                        orchestration_scan_id,
                    )
                    total_findings += len(findings)
                    processed_files["cloudsplaining"] = [str(report)]

        # Register all processed files with the scan
        for tool, files in processed_files.items():
            if files:
                self._register_scan_files(orchestration_scan_id, tool, files)

        # ========================================================================
        # Attack Validation Features (v2)
        # ========================================================================
        self._run_attack_validation_features(orchestration_scan_id)

        # Summary logging with diagnostic hints
        if total_findings == 0:
            logger.warning(
                f"ZERO findings processed for scan {orchestration_scan_id}. "
                "This may indicate a problem with report discovery or permissions."
            )
            logger.warning(f"Tools requested: {tools_to_process}")
            logger.warning(f"Processed files: {processed_files}")
            logger.warning(
                "If running on Linux, ensure reports directory is readable: "
                "sudo chmod -R 755 ./reports"
            )
        else:
            logger.info(f"Successfully processed {total_findings} findings for scan {orchestration_scan_id}")
            logger.info(f"Processed files by tool: {list(processed_files.keys())}")

        return total_findings

    def _run_attack_validation_features(self, scan_id: str):
        """Run attack validation features based on user settings."""
        conn = self._get_db_connection()
        if not conn:
            logger.warning("Cannot run attack validation features: database unavailable")
            return

        try:
            settings = self._get_validation_settings(conn)

            if settings.get("blast_radius_auto_analyze", True) and BlastRadiusAnalyzer:
                try:
                    logger.info(f"Running blast radius analysis for scan {scan_id}")
                    analyzer = BlastRadiusAnalyzer(conn)
                    results = analyzer.analyze_for_scan(scan_id)
                    logger.info(f"Blast radius analysis complete: {len(results)} identities analyzed")
                except Exception as e:
                    logger.warning(f"Blast radius analysis failed (non-fatal): {e}")

            if settings.get("auto_validate_poc", False) and PoCValidator:
                try:
                    logger.info(f"Running PoC validation for scan {scan_id}")
                    validator = PoCValidator(conn)
                    results = validator.validate_attack_paths_for_scan(scan_id, severity_filter="high")
                    validated = sum(1 for r in results if r.get("validation_status") == "validated_exploitable")
                    logger.info(f"PoC validation complete: {validated}/{len(results)} paths validated as exploitable")
                except Exception as e:
                    logger.warning(f"PoC validation failed (non-fatal): {e}")

            if settings.get("cloudtrail_correlation", False) and RuntimeCorrelator:
                try:
                    logger.info(f"Running runtime correlation for scan {scan_id}")
                    try:
                        lookback_hours = int(settings.get("cloudtrail_lookback_hours", 24))
                    except (ValueError, TypeError):
                        lookback_hours = 24
                    correlator = RuntimeCorrelator(conn)
                    results = correlator.correlate_for_scan(scan_id, lookback_hours=lookback_hours)
                    confirmed = sum(1 for r in results if r.get("confirms_exploitability", False))
                    logger.info(f"Runtime correlation complete: {confirmed} findings confirmed by CloudTrail events")
                except Exception as e:
                    logger.warning(f"Runtime correlation failed (non-fatal): {e}")
        finally:
            conn.close()

    def _get_validation_settings(self, conn) -> dict:
        """Retrieve validation feature settings from user_settings table."""
        settings = {}
        validation_keys = [
            "auto_validate_poc",
            "cloudtrail_correlation",
            "blast_radius_auto_analyze",
            "poc_validation_timeout",
            "cloudtrail_lookback_hours",
        ]
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT setting_key, setting_value
                    FROM user_settings
                    WHERE setting_key = ANY(%s)
                    """,
                    (validation_keys,),
                )
                for row in cur.fetchall():
                    key, value = row
                    if value is None:
                        continue
                    if isinstance(value, str):
                        if value.lower() in ("true", "false"):
                            settings[key] = value.lower() == "true"
                        else:
                            settings[key] = value
                    else:
                        settings[key] = value
        except Exception as e:
            logger.warning(f"Could not retrieve validation settings: {e}")
        return settings

    def run(self):
        """Main processing loop"""
        logger.info("Starting report processing...")

        # Process ScoutSuite reports (JavaScript format in scoutsuite-results/ subdirectory)
        scoutsuite_reports = list(self.reports_dir.glob("scoutsuite/*/scoutsuite-results/*.js"))
        scoutsuite_reports += list(self.reports_dir.glob("scoutsuite/*/scoutsuite_results_*.json"))
        scoutsuite_reports = list(set(scoutsuite_reports))
        for report in scoutsuite_reports:
            scan_id = f"scoutsuite_{report.parent.parent.name if report.suffix == '.js' else report.parent.name}"
            metadata, findings = self.process_scoutsuite_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process Prowler reports (both legacy and OCSF formats)
        prowler_reports = list(self.reports_dir.glob("prowler/*/prowler-output-*.json"))
        prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.json"))
        prowler_reports += list(self.reports_dir.glob("prowler/prowler-output-*.ocsf.json"))
        prowler_reports = list(set(prowler_reports))
        for report in prowler_reports:
            scan_id = f"prowler_{report.stem}"
            metadata, findings = self.process_prowler_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process kube-linter reports
        kube_linter_reports = list(self.reports_dir.glob("kube-linter/*.json"))
        for report in kube_linter_reports:
            scan_id = f"kube_linter_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_kube_linter_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process Polaris reports
        polaris_reports = list(self.reports_dir.glob("polaris/*.json"))
        for report in polaris_reports:
            scan_id = f"polaris_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_polaris_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process CloudSploit reports
        cloudsploit_reports = list(self.reports_dir.glob("cloudsploit/*.json"))
        for report in cloudsploit_reports:
            scan_id = f"cloudsploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_cloudsploit_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Generate unified report
        self.generate_unified_report()

        logger.info("Report processing completed")


if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="Process security scan reports")
    parser.add_argument(
        "--scan-id", dest="scan_id", help="Orchestration scan UUID to link findings to"
    )
    parser.add_argument(
        "--tools",
        dest="tools",
        help="Comma-separated list of tools to process (e.g., prowler,scoutsuite)",
    )
    parser.add_argument(
        "--auto-process",
        dest="auto_process",
        action="store_true",
        help="Auto-process all existing reports on startup",
    )
    parser.add_argument(
        "--retry-dead-letters",
        dest="retry_dead_letters",
        action="store_true",
        help="Retry all dead-lettered finding batches and exit",
    )
    args = parser.parse_args()

    # Also check environment variables (for container deployment)
    scan_id = args.scan_id or os.environ.get("ORCHESTRATION_SCAN_ID")
    tools_str = args.tools or os.environ.get("TOOLS_TO_PROCESS")
    tools = tools_str.split(",") if tools_str else None

    # Check if auto-processing is enabled (default: disabled)
    auto_process = args.auto_process or os.environ.get("AUTO_PROCESS", "false").lower() == "true"

    processor = ReportProcessor()

    if args.retry_dead_letters:
        logger.info("Retrying dead-lettered finding batches...")
        summary = _retry_dead_letters(processor.db_config)
        print(f"Dead-letter retry summary: {summary}")
        raise SystemExit(0)

    if scan_id:
        # Process for a specific orchestration scan
        logger.info(f"Processing reports for orchestration scan: {scan_id}")
        total = processor.process_for_scan(scan_id, tools)
        logger.info(f"Completed: {total} findings linked to scan {scan_id}")
    elif auto_process:
        # Run full processing loop only if explicitly enabled
        logger.info("Auto-processing enabled, running full report processing")
        processor.run()
    else:
        # Default: wait for explicit triggers (scans will trigger processing via API)
        logger.info("Report processor started in standby mode (AUTO_PROCESS=false)")
        logger.info("Processing will be triggered by scan completions via API")
        # Keep container alive but don't auto-process
        while True:
            time.sleep(3600)  # Sleep for 1 hour, wake up to check for signals
