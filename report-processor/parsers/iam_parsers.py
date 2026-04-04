"""IAM analysis tool parsers: PMapper, Cloudsplaining."""

import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def process_pmapper_report(report_path, discovered_account_id=None):
    """Process PMapper JSON report for IAM privilege escalation analysis."""
    logger.info(f"Processing PMapper report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        account_id = discovered_account_id or "unknown"

        metadata = {
            "tool": "pmapper",
            "cloud_provider": "aws",
            "scan_date": datetime.now().isoformat(),
            "account_id": account_id,
        }

        if isinstance(data, list):
            for item in data:
                source_principal = item.get("source") or item.get("principal") or "unknown"
                target_principal = item.get("target") or item.get("admin_principal") or ""
                escalation_method = item.get("method") or item.get("edge_type") or "unknown"
                is_admin = item.get("is_admin", False)

                if is_admin:
                    severity = "critical"
                    title = f"Admin Access: {source_principal}"
                    description = f"Principal {source_principal} has admin-level access to the AWS account"
                elif target_principal:
                    severity = "high"
                    title = f"Privilege Escalation Path: {source_principal}"
                    description = f"Principal {source_principal} can escalate privileges to {target_principal} via {escalation_method}"
                else:
                    severity = "medium"
                    title = f"IAM Finding: {source_principal}"
                    description = f"IAM finding for principal {source_principal}"

                evidence_obj = {
                    "source_principal": source_principal,
                    "target_principal": target_principal,
                    "escalation_method": escalation_method,
                    "is_admin": is_admin,
                    "raw_data": item,
                }

                finding = {
                    "check_id": f"pmapper-privesc-{escalation_method.lower().replace(' ', '-') if escalation_method else 'unknown'}",
                    "check_title": title,
                    "severity": severity,
                    "status": "open",
                    "region": "global",
                    "resource_id": source_principal,
                    "resource_type": "iam-principal",
                    "resource_name": source_principal.split("/")[-1] if "/" in source_principal else source_principal,
                    "account_id": account_id,
                    "description": description,
                    "remediation": "Review and restrict IAM permissions to follow the principle of least privilege. Remove unnecessary privilege escalation paths.",
                    "compliance": [],
                    "poc_evidence": json.dumps(evidence_obj, indent=2),
                    "poc_verification": f"Source: {source_principal}\nTarget: {target_principal or 'N/A'}\nMethod: {escalation_method}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [
                        {
                            "title": "PMapper Documentation",
                            "url": "https://github.com/nccgroup/PMapper",
                            "type": "documentation",
                        }
                    ],
                }
                findings.append(finding)
        elif isinstance(data, dict):
            if "edges" in data:
                for edge in data.get("edges", []):
                    source = edge.get("source", "unknown")
                    destination = edge.get("destination", "")
                    edge_type = edge.get("edge_type", "unknown")

                    evidence_obj = {
                        "source": source,
                        "destination": destination,
                        "edge_type": edge_type,
                    }

                    finding = {
                        "check_id": f"pmapper-edge-{edge_type.lower().replace(' ', '-')}",
                        "check_title": f"IAM Relationship: {edge_type}",
                        "severity": "medium",
                        "status": "open",
                        "region": "global",
                        "resource_id": source,
                        "resource_type": "iam-principal",
                        "resource_name": source.split("/")[-1] if "/" in source else source,
                        "account_id": account_id,
                        "description": f"IAM principal {source} has {edge_type} relationship to {destination}",
                        "remediation": "Review IAM relationships and ensure least privilege access.",
                        "compliance": [],
                        "poc_evidence": json.dumps(evidence_obj, indent=2),
                        "poc_verification": f"Source: {source}\nDestination: {destination}\nType: {edge_type}",
                        "remediation_commands": [],
                        "remediation_code": {},
                        "remediation_resources": [],
                    }
                    findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from PMapper")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing PMapper report: {e}")
        return None, []


def process_cloudsplaining_report(report_path, discovered_account_id=None):
    """Process Cloudsplaining JSON report for IAM policy analysis."""
    logger.info(f"Processing Cloudsplaining report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        account_id = data.get("account_id", discovered_account_id or "unknown")

        metadata = {
            "tool": "cloudsplaining",
            "cloud_provider": "aws",
            "scan_date": datetime.now().isoformat(),
            "account_id": account_id,
        }

        risk_categories = [
            ("privilege_escalation", "critical", "Privilege Escalation"),
            ("resource_exposure", "high", "Resource Exposure"),
            ("infrastructure_modification", "medium", "Infrastructure Modification"),
            ("data_exfiltration", "high", "Data Exfiltration"),
        ]

        for category_key, severity, category_name in risk_categories:
            category_findings = data.get(category_key, [])
            if not isinstance(category_findings, list):
                continue

            for item in category_findings:
                if isinstance(item, dict):
                    policy_name = item.get("PolicyName", item.get("policy_name", "unknown"))
                    policy_type = item.get("Type", item.get("type", "unknown"))
                    actions = item.get("Actions", item.get("actions", []))
                    services = item.get("Services", item.get("services", []))
                elif isinstance(item, str):
                    policy_name = item
                    policy_type = "unknown"
                    actions = []
                    services = []
                else:
                    continue

                evidence_obj = {
                    "policy_name": policy_name,
                    "policy_type": policy_type,
                    "risk_category": category_key,
                    "actions": actions[:20] if isinstance(actions, list) else [],
                    "services": services[:10] if isinstance(services, list) else [],
                }

                finding = {
                    "check_id": f"cloudsplaining-{category_key.replace('_', '-')}",
                    "check_title": f"{category_name}: {policy_name}",
                    "severity": severity,
                    "status": "open",
                    "region": "global",
                    "resource_id": policy_name,
                    "resource_type": "iam-policy",
                    "resource_name": policy_name,
                    "account_id": account_id,
                    "description": f"IAM policy {policy_name} ({policy_type}) has {category_name.lower()} risk. Affected services: {', '.join(services[:5]) if services else 'N/A'}",
                    "remediation": f"Review and restrict the {policy_name} policy to follow least privilege. Remove unnecessary {category_name.lower()} permissions.",
                    "compliance": [],
                    "poc_evidence": json.dumps(evidence_obj, indent=2),
                    "poc_verification": f"Policy: {policy_name}\nType: {policy_type}\nRisk: {category_name}",
                    "remediation_commands": [],
                    "remediation_code": {},
                    "remediation_resources": [
                        {
                            "title": "Cloudsplaining Documentation",
                            "url": "https://github.com/salesforce/cloudsplaining",
                            "type": "documentation",
                        }
                    ],
                }
                findings.append(finding)

        for policy_section in ["inline_policies", "customer_managed_policies", "aws_managed_policies"]:
            policies = data.get(policy_section, [])
            if not isinstance(policies, list):
                continue

            for policy in policies:
                if not isinstance(policy, dict):
                    continue

                policy_name = policy.get("PolicyName", policy.get("policy_name", "unknown"))
                risks = policy.get("risks", {})

                for risk_type, risk_actions in risks.items() if isinstance(risks, dict) else []:
                    if not risk_actions:
                        continue

                    risk_severity_map = {
                        "PrivilegeEscalation": "critical",
                        "ResourceExposure": "high",
                        "DataExfiltration": "high",
                        "InfrastructureModification": "medium",
                    }
                    severity = risk_severity_map.get(risk_type, "medium")

                    evidence_obj = {
                        "policy_name": policy_name,
                        "policy_section": policy_section,
                        "risk_type": risk_type,
                        "risky_actions": risk_actions[:20] if isinstance(risk_actions, list) else [],
                    }

                    finding = {
                        "check_id": f"cloudsplaining-policy-{risk_type.lower()}",
                        "check_title": f"{risk_type}: {policy_name}",
                        "severity": severity,
                        "status": "open",
                        "region": "global",
                        "resource_id": policy_name,
                        "resource_type": "iam-policy",
                        "resource_name": policy_name,
                        "account_id": account_id,
                        "description": f"Policy {policy_name} contains {risk_type} risk with {len(risk_actions) if isinstance(risk_actions, list) else 0} risky actions",
                        "remediation": f"Review the {policy_name} policy and remove or restrict {risk_type} permissions.",
                        "compliance": [],
                        "poc_evidence": json.dumps(evidence_obj, indent=2),
                        "poc_verification": f"Policy: {policy_name}\nRisk Type: {risk_type}",
                        "remediation_commands": [],
                        "remediation_code": {},
                        "remediation_resources": [],
                    }
                    findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from Cloudsplaining")
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing Cloudsplaining report: {e}")
        return None, []
