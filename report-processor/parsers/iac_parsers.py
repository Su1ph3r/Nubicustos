"""IaC security tool parsers: KubeLinter, Polaris, Checkov, Terrascan, Tfsec."""

import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def process_kube_linter_report(report_path):
    """Process kube-linter JSON report."""
    logger.info(f"Processing kube-linter report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        metadata = {
            "tool": "kube-linter",
            "cloud_provider": "kubernetes",
            "scan_date": datetime.now().isoformat(),
        }

        for item in data.get("Reports", []):
            k8s_obj = item.get("Object", {}).get("K8sObject", {})
            for violation in item.get("Violations", []):
                severity_map = {"error": "high", "warning": "medium", "info": "low"}

                finding = {
                    "check_id": violation.get("Check", ""),
                    "check_title": violation.get("Check", ""),
                    "severity": severity_map.get(
                        violation.get("Severity", "warning").lower(), "medium"
                    ),
                    "status": "FAIL",
                    "resource_type": k8s_obj.get("GroupVersionKind", {}).get("Kind", ""),
                    "resource_id": f"{k8s_obj.get('Namespace', 'default')}/{k8s_obj.get('Name', '')}",
                    "resource_name": k8s_obj.get("Name", ""),
                    "description": violation.get("Message", ""),
                    "remediation": violation.get("Remediation", ""),
                    "compliance": [],
                }
                findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from kube-linter")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing kube-linter report: {e}")
        return None, []


def process_polaris_report(report_path):
    """Process Polaris JSON report."""
    logger.info(f"Processing Polaris report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        metadata = {
            "tool": "polaris",
            "cloud_provider": "kubernetes",
            "scan_date": datetime.now().isoformat(),
            "cluster_info": data.get("ClusterInfo", {}),
        }

        severity_map = {
            "danger": "critical",
            "warning": "medium",
            "passing": "info",
        }

        for namespace_name, namespace_data in data.get("Results", {}).items():
            if not isinstance(namespace_data, dict):
                continue
            for controller_name, controller_data in namespace_data.items():
                if not isinstance(controller_data, dict):
                    continue

                kind = controller_data.get("Kind", "Unknown")

                for container_name, container_results in controller_data.get(
                    "Results", {}
                ).items():
                    if not isinstance(container_results, dict):
                        continue

                    for check_category, checks in container_results.items():
                        if not isinstance(checks, dict):
                            continue

                        for check_name, check_result in checks.items():
                            if not isinstance(check_result, dict):
                                continue

                            if check_result.get("Success", True):
                                continue

                            severity_level = check_result.get("Severity", "warning")

                            finding = {
                                "check_id": f"polaris-{check_category}-{check_name}",
                                "check_title": check_name.replace("_", " ").title(),
                                "severity": severity_map.get(severity_level, "medium"),
                                "status": "FAIL",
                                "resource_type": kind,
                                "resource_id": f"{namespace_name}/{controller_name}",
                                "resource_name": controller_name,
                                "category": check_category,
                                "container": container_name,
                                "description": check_result.get("Message", ""),
                                "remediation": f"Review and fix {check_name} for {kind} {controller_name}",
                                "compliance": [],
                            }
                            findings.append(finding)

        for pod_result in data.get("PodResults", []):
            namespace = pod_result.get("Namespace", "default")
            pod_name = pod_result.get("Name", "")
            kind = pod_result.get("Kind", "Pod")

            for container_result in pod_result.get("ContainerResults", []):
                container_name = container_result.get("Name", "")

                for check_name, check_result in container_result.get("Results", {}).items():
                    if not isinstance(check_result, dict):
                        continue
                    if check_result.get("Success", True):
                        continue

                    severity_level = check_result.get("Severity", "warning")

                    finding = {
                        "check_id": f"polaris-{check_name}",
                        "check_title": check_name.replace("_", " ").title(),
                        "severity": severity_map.get(severity_level, "medium"),
                        "status": "FAIL",
                        "resource_type": kind,
                        "resource_id": f"{namespace}/{pod_name}",
                        "resource_name": pod_name,
                        "container": container_name,
                        "description": check_result.get("Message", ""),
                        "remediation": f"Review and fix {check_name} for container {container_name}",
                        "compliance": [],
                    }
                    findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from Polaris")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing Polaris report: {e}")
        return None, []


def process_checkov_report(report_path):
    """Process Checkov JSON report for IaC security findings."""
    logger.info(f"Processing Checkov report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        metadata = {
            "tool": "checkov",
            "cloud_provider": "iac",
            "scan_date": datetime.now().isoformat(),
        }

        check_types = data if isinstance(data, list) else [data]

        for check_type_data in check_types:
            check_type = check_type_data.get("check_type", "unknown")

            for check in check_type_data.get("results", {}).get("failed_checks", []):
                severity_map = {
                    "CRITICAL": "critical",
                    "HIGH": "high",
                    "MEDIUM": "medium",
                    "LOW": "low",
                    "INFO": "info",
                }
                raw_severity = check.get("severity") or "MEDIUM"
                severity = severity_map.get(raw_severity.upper(), "medium")

                finding = {
                    "check_id": check.get("check_id", ""),
                    "check_title": check.get("check_name", check.get("check_id", "")),
                    "severity": severity,
                    "status": "FAIL",
                    "resource_type": check.get("resource", "").split(".")[-1]
                    if check.get("resource")
                    else check_type,
                    "resource_id": check.get("resource_address", check.get("resource", "")),
                    "resource_name": check.get("resource", ""),
                    "region": "iac",
                    "description": check.get("check_name", ""),
                    "remediation": check.get("guideline", ""),
                    "compliance": [],
                    "poc_evidence": json.dumps(
                        {
                            "check_id": check.get("check_id", ""),
                            "file_path": check.get("file_path", ""),
                            "file_line_range": check.get("file_line_range", []),
                            "code_block": check.get("code_block", ""),
                            "check_class": check.get("check_class", ""),
                        },
                        indent=2,
                    ),
                    "poc_verification": f"File: {check.get('file_path', 'unknown')}\n"
                    f"Lines: {check.get('file_line_range', 'N/A')}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [
                        {
                            "title": "Checkov Documentation",
                            "url": f"https://www.checkov.io/5.Policy%20Index/{check.get('check_id', '')}.html",
                            "type": "documentation",
                        }
                    ]
                    if check.get("check_id")
                    else [],
                }
                findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from Checkov")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing Checkov report: {e}")
        return None, []


def process_terrascan_report(report_path):
    """Process Terrascan JSON report for IaC security findings."""
    logger.info(f"Processing Terrascan report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        metadata = {
            "tool": "terrascan",
            "cloud_provider": "iac",
            "scan_date": datetime.now().isoformat(),
        }

        results = data.get("results", {})

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for violation in results.get("violations", []):
            raw_severity = violation.get("severity") or "MEDIUM"
            severity = severity_map.get(raw_severity.upper(), "medium")

            finding = {
                "check_id": violation.get("rule_id", violation.get("rule_name", "")),
                "check_title": violation.get("rule_name", violation.get("description", "")),
                "severity": severity,
                "status": "FAIL",
                "resource_type": violation.get("resource_type", ""),
                "resource_id": violation.get("resource_name", violation.get("file", "")),
                "resource_name": violation.get("resource_name", ""),
                "region": "iac",
                "description": violation.get("description", ""),
                "remediation": violation.get("remediation", ""),
                "compliance": [],
                "poc_evidence": json.dumps(
                    {
                        "rule_id": violation.get("rule_id", ""),
                        "file": violation.get("file", ""),
                        "line": violation.get("line", 0),
                        "resource_type": violation.get("resource_type", ""),
                        "category": violation.get("category", ""),
                    },
                    indent=2,
                ),
                "poc_verification": f"File: {violation.get('file', 'unknown')}\n"
                f"Line: {violation.get('line', 'N/A')}",
                "remediation_commands": [],
                "remediation_code": {},
                "remediation_resources": [],
            }
            findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from Terrascan")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing Terrascan report: {e}")
        return None, []


def process_tfsec_report(report_path):
    """Process tfsec JSON report for Terraform security findings."""
    logger.info(f"Processing tfsec report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        metadata = {
            "tool": "tfsec",
            "cloud_provider": "iac",
            "scan_date": datetime.now().isoformat(),
        }

        results = data.get("results", []) if isinstance(data, dict) else data

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for result in results:
            raw_severity = result.get("severity") or "MEDIUM"
            severity = severity_map.get(raw_severity.upper(), "medium")

            location = result.get("location", {})
            filename = location.get("filename", "unknown")
            start_line = location.get("start_line", 0)
            end_line = location.get("end_line", 0)

            finding = {
                "check_id": result.get("rule_id", result.get("long_id", "")),
                "check_title": result.get("rule_description", result.get("description", "")),
                "severity": severity,
                "status": "FAIL",
                "resource_type": result.get("resource", "").split(".")[-1]
                if result.get("resource")
                else "terraform",
                "resource_id": result.get("resource", filename),
                "resource_name": result.get("resource", ""),
                "region": "iac",
                "description": result.get("description", ""),
                "remediation": result.get("resolution", result.get("impact", "")),
                "compliance": [],
                "poc_evidence": json.dumps(
                    {
                        "rule_id": result.get("rule_id", ""),
                        "rule_provider": result.get("rule_provider", ""),
                        "rule_service": result.get("rule_service", ""),
                        "file": filename,
                        "lines": f"{start_line}-{end_line}",
                    },
                    indent=2,
                ),
                "poc_verification": f"File: {filename}\nLines: {start_line}-{end_line}",
                "remediation_commands": [],
                "remediation_code": {},
                "remediation_resources": [
                    {
                        "title": "tfsec Documentation",
                        "url": result["links"][0],
                        "type": "documentation",
                    }
                ]
                if result.get("links") and len(result["links"]) > 0
                else [],
            }
            findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from tfsec")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing tfsec report: {e}")
        return None, []
