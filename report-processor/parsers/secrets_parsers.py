"""Secrets scanning tool parsers: TruffleHog, Gitleaks."""

import json
import logging
from datetime import datetime

from .utils import redact_secret

logger = logging.getLogger(__name__)


def process_trufflehog_report(report_path, discovered_account_id=None):
    """Process TruffleHog JSON report for secrets scanning."""
    logger.info(f"Processing TruffleHog report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            content = f.read()

        metadata = {
            "tool": "trufflehog",
            "cloud_provider": "secrets",
            "scan_date": datetime.now().isoformat(),
        }

        for line in content.split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)

                if "level" in item and "SourceMetadata" not in item:
                    continue

                if "SourceMetadata" not in item and "Raw" not in item:
                    continue

                source_metadata = item.get("SourceMetadata", {})
                source_data = source_metadata.get("Data", {})
                filesystem_data = source_data.get("Filesystem", {})

                file_path = filesystem_data.get("file", "unknown")
                line_number = filesystem_data.get("line", 0)

                detector_name = item.get("DetectorName", "unknown")
                detector_type = item.get("DetectorType", 0)

                verified = item.get("Verified", False)

                if verified:
                    severity = "critical"
                elif detector_name.lower() in ["aws", "gcp", "azure", "github"]:
                    severity = "high"
                else:
                    severity = "medium"

                raw_secret = item.get("Raw", "")
                redacted = redact_secret(raw_secret)

                evidence_obj = {
                    "detector_name": detector_name,
                    "detector_type": detector_type,
                    "verified": verified,
                    "file": file_path,
                    "line": line_number,
                    "redacted_secret": redacted,
                }

                finding = {
                    "check_id": f"trufflehog-{detector_name.lower().replace(' ', '-')}",
                    "check_title": f"Secret Detected: {detector_name}",
                    "severity": severity,
                    "status": "open",
                    "region": "secrets",
                    "resource_id": file_path,
                    "resource_type": "secret",
                    "resource_name": f"{file_path}:{line_number}",
                    "account_id": discovered_account_id or "unknown",
                    "description": f"{'Verified ' if verified else ''}secret detected by {detector_name} detector in {file_path} at line {line_number}",
                    "remediation": "Remove the secret from the codebase and rotate the credential immediately. Store secrets in a secure secrets manager.",
                    "compliance": [],
                    "poc_evidence": json.dumps(evidence_obj, indent=2),
                    "poc_verification": f"File: {file_path}\nLine: {line_number}\nDetector: {detector_name}\nVerified: {verified}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [
                        {
                            "title": "TruffleHog Documentation",
                            "url": "https://trufflesecurity.com/trufflehog",
                            "type": "documentation",
                        }
                    ],
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        logger.info(f"Extracted {len(findings)} findings from TruffleHog")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing TruffleHog report: {e}")
        return None, []


def process_gitleaks_report(report_path, discovered_account_id=None):
    """Process Gitleaks JSON report for secrets scanning."""
    logger.info(f"Processing Gitleaks report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        metadata = {
            "tool": "gitleaks",
            "cloud_provider": "secrets",
            "scan_date": datetime.now().isoformat(),
        }

        if not isinstance(data, list):
            logger.warning(f"Gitleaks report is not a JSON array: {report_path}")
            return None, []

        high_severity_rules = {
            "aws-access-key-id", "aws-secret-access-key", "github-pat",
            "github-oauth", "gitlab-pat", "gcp-api-key", "azure-storage-key",
            "private-key", "jwt", "slack-token", "stripe-api-key",
        }

        for item in data:
            rule_id = item.get("RuleID", "unknown")

            if rule_id.lower() in high_severity_rules:
                severity = "high"
            else:
                severity = "medium"

            file_path = item.get("File", "unknown")
            line_number = item.get("StartLine", item.get("Line", 0))

            raw_secret = item.get("Secret", "")
            redacted = redact_secret(raw_secret)

            evidence_obj = {
                "rule_id": rule_id,
                "description": item.get("Description", ""),
                "file": file_path,
                "start_line": line_number,
                "end_line": item.get("EndLine", line_number),
                "redacted_secret": redacted,
                "fingerprint": item.get("Fingerprint", ""),
            }

            finding = {
                "check_id": f"gitleaks-{rule_id.lower()}",
                "check_title": item.get("Description", f"Secret Detected: {rule_id}"),
                "severity": severity,
                "status": "open",
                "region": "secrets",
                "resource_id": file_path,
                "resource_type": "secret",
                "resource_name": f"{file_path}:{line_number}",
                "account_id": discovered_account_id or "unknown",
                "description": f"Secret detected by {rule_id} rule in {file_path} at line {line_number}. {item.get('Description', '')}",
                "remediation": "Remove the secret from the codebase and rotate the credential immediately. Store secrets in a secure secrets manager.",
                "compliance": [],
                "poc_evidence": json.dumps(evidence_obj, indent=2),
                "poc_verification": f"File: {file_path}\nLine: {line_number}\nRule: {rule_id}",
                "remediation_commands": [],
                "remediation_code": {},
                "remediation_resources": [
                    {
                        "title": "Gitleaks Documentation",
                        "url": "https://github.com/gitleaks/gitleaks",
                        "type": "documentation",
                    }
                ],
            }
            findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from Gitleaks")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing Gitleaks report: {e}")
        return None, []
