"""
IMDS (Instance Metadata Service) Context Enricher.

This module enhances IMDS-related findings with additional context,
risk factors, and remediation commands.

IMDS vulnerabilities are a common attack vector in cloud environments,
particularly AWS EC2, allowing credential theft and privilege escalation.

Risk factors evaluated:
- IMDSv1 enabled (allows direct credential retrieval)
- High hop limit (allows container/pod access)
- IMDS access from containers
- Missing IMDS endpoint restrictions

Storage: finding["threat_intel_enrichment"]["imds_context"]
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# IMDS-related keywords for detection
IMDS_KEYWORDS = [
    "imds",
    "instance metadata",
    "metadata service",
    "169.254.169.254",
    "metadata endpoint",
    "imdsv1",
    "imdsv2",
    "http tokens",
    "metadata-token",
    "ec2metadata",
    "link-local",
    "credential exposure",
    "metadata credentials",
]

# Risk factor definitions
IMDS_RISK_FACTORS = {
    "imdsv1_enabled": {
        "score": 25,
        "mitre_technique": "T1552.005",
        "mitre_name": "Cloud Instance Metadata API",
        "description": "IMDSv1 enabled allows direct credential retrieval without session tokens",
        "keywords": ["imdsv1", "http tokens optional", "httptokens: optional", "v1 endpoint"],
        "remediation_priority": "critical",
    },
    "high_hop_limit": {
        "score": 15,
        "mitre_technique": "T1552.005",
        "mitre_name": "Cloud Instance Metadata API",
        "description": "Hop limit > 1 allows container/pod access to instance metadata",
        "keywords": ["hop limit", "hoplimit", "httpputresponsehoplimit"],
        "remediation_priority": "high",
    },
    "container_imds_access": {
        "score": 20,
        "mitre_technique": "T1552.005",
        "mitre_name": "Cloud Instance Metadata API",
        "description": "Containers can access instance metadata service",
        "keywords": ["container", "pod", "ecs task", "fargate"],
        "remediation_priority": "high",
    },
    "no_imds_restriction": {
        "score": 15,
        "mitre_technique": "T1552.005",
        "mitre_name": "Cloud Instance Metadata API",
        "description": "No network restrictions on IMDS endpoint access",
        "keywords": ["unrestricted", "no restriction", "all access"],
        "remediation_priority": "medium",
    },
    "ssrf_to_imds": {
        "score": 30,
        "mitre_technique": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "SSRF vulnerability allowing IMDS access",
        "keywords": ["ssrf", "server-side request forgery", "url redirect"],
        "remediation_priority": "critical",
    },
}

# AWS CLI remediation command templates
AWS_REMEDIATION_COMMANDS = {
    "require_imdsv2": {
        "description": "Require IMDSv2 (disable IMDSv1)",
        "command": 'aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-tokens required --http-endpoint enabled',
        "explanation": "Forces IMDSv2 which requires session tokens for credential retrieval",
    },
    "reduce_hop_limit": {
        "description": "Reduce hop limit to 1 (block container access)",
        "command": 'aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-put-response-hop-limit 1',
        "explanation": "Prevents containers from accessing IMDS by limiting network hops",
    },
    "disable_imds": {
        "description": "Disable IMDS entirely (use IAM roles instead)",
        "command": 'aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-endpoint disabled',
        "explanation": "Completely disables IMDS - ensure IAM roles are used for credentials",
    },
    "block_imds_in_container": {
        "description": "Block IMDS access from container (iptables)",
        "command": "iptables -A OUTPUT -d 169.254.169.254 -j DROP",
        "explanation": "Network-level block of IMDS endpoint from within container",
    },
}


def _is_imds_finding(finding: dict[str, Any]) -> bool:
    """
    Check if a finding is IMDS-related.

    Args:
        finding: The finding dictionary

    Returns:
        True if IMDS-related
    """
    check_fields = [
        finding.get("check_title", ""),
        finding.get("title", ""),
        finding.get("check_id", ""),
        finding.get("description", ""),
    ]

    combined = " ".join(str(f).lower() for f in check_fields if f)

    return any(keyword in combined for keyword in IMDS_KEYWORDS)


def _detect_imds_risk_factors(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Detect IMDS-specific risk factors in a finding.

    Args:
        finding: The finding dictionary

    Returns:
        List of detected risk factors
    """
    detected = []

    search_fields = [
        finding.get("check_title", ""),
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("poc_evidence", ""),
        finding.get("resource_details", ""),
    ]

    combined_text = " ".join(str(f).lower() for f in search_fields if f)

    for factor_id, factor_info in IMDS_RISK_FACTORS.items():
        for keyword in factor_info["keywords"]:
            if keyword.lower() in combined_text:
                detected.append({
                    "factor_id": factor_id,
                    "score": factor_info["score"],
                    "mitre_technique": factor_info["mitre_technique"],
                    "mitre_name": factor_info["mitre_name"],
                    "description": factor_info["description"],
                    "remediation_priority": factor_info["remediation_priority"],
                    "matched_keyword": keyword,
                })
                break

    return detected


def _extract_instance_id(finding: dict[str, Any]) -> str | None:
    """
    Extract EC2 instance ID from finding.

    Args:
        finding: The finding dictionary

    Returns:
        Instance ID or None
    """
    # Pattern for EC2 instance IDs
    instance_pattern = r"i-[0-9a-f]{8,17}"

    search_fields = [
        finding.get("resource_id", ""),
        finding.get("resource_arn", ""),
        finding.get("description", ""),
        finding.get("poc_evidence", ""),
    ]

    combined = " ".join(str(f) for f in search_fields if f)

    match = re.search(instance_pattern, combined, re.IGNORECASE)
    return match.group(0) if match else None


def _get_remediation_commands(
    factors: list[dict[str, Any]], instance_id: str | None
) -> list[dict[str, str]]:
    """
    Generate remediation commands based on detected risk factors.

    Args:
        factors: List of detected risk factors
        instance_id: Optional instance ID for templating

    Returns:
        List of remediation command dicts
    """
    commands = []
    instance_id_placeholder = instance_id or "<INSTANCE_ID>"

    # Determine which commands to include based on factors
    factor_ids = {f["factor_id"] for f in factors}

    if "imdsv1_enabled" in factor_ids:
        cmd = AWS_REMEDIATION_COMMANDS["require_imdsv2"].copy()
        cmd["command"] = cmd["command"].format(instance_id=instance_id_placeholder)
        commands.append(cmd)

    if "high_hop_limit" in factor_ids or "container_imds_access" in factor_ids:
        cmd = AWS_REMEDIATION_COMMANDS["reduce_hop_limit"].copy()
        cmd["command"] = cmd["command"].format(instance_id=instance_id_placeholder)
        commands.append(cmd)

        # Also include iptables option for containers
        if "container_imds_access" in factor_ids:
            commands.append(AWS_REMEDIATION_COMMANDS["block_imds_in_container"].copy())

    # Always suggest the nuclear option for critical issues
    if any(f["remediation_priority"] == "critical" for f in factors):
        cmd = AWS_REMEDIATION_COMMANDS["disable_imds"].copy()
        cmd["command"] = cmd["command"].format(instance_id=instance_id_placeholder)
        cmd["description"] = "(Alternative) " + cmd["description"]
        commands.append(cmd)

    return commands


def enrich_with_imds_context(finding: dict[str, Any]) -> dict[str, Any] | None:
    """
    Enrich a finding with IMDS context and remediation.

    Args:
        finding: The finding dictionary

    Returns:
        Enrichment result dict or None if not IMDS-related
    """
    # Only process IMDS-related findings
    if not _is_imds_finding(finding):
        return None

    # Detect risk factors
    factors = _detect_imds_risk_factors(finding)

    # If no specific factors detected but it's an IMDS finding,
    # add a generic risk factor
    if not factors:
        factors = [{
            "factor_id": "imds_misconfiguration",
            "score": 15,
            "mitre_technique": "T1552.005",
            "mitre_name": "Cloud Instance Metadata API",
            "description": "IMDS-related security finding",
            "remediation_priority": "medium",
            "matched_keyword": "imds",
        }]

    # Extract instance ID if available
    instance_id = _extract_instance_id(finding)

    # Get remediation commands
    remediation_commands = _get_remediation_commands(factors, instance_id)

    # Calculate total score
    total_score = min(100, sum(f["score"] for f in factors))

    # Build result
    result = {
        "risk_factors": factors,
        "total_risk_score": total_score,
        "factor_count": len(factors),
        "instance_id": instance_id,
        "remediation_commands": remediation_commands,
        "mitre_techniques": list(set(
            f"{f['mitre_technique']} ({f['mitre_name']})" for f in factors
        )),
        "attack_context": {
            "attack_type": "Cloud Credential Theft",
            "impact": "Compromise of IAM role credentials attached to instance",
            "typical_chain": [
                "1. Attacker gains code execution (SSRF, RCE, container escape)",
                "2. Queries IMDS at 169.254.169.254",
                "3. Retrieves temporary IAM credentials",
                "4. Uses credentials for lateral movement or data exfiltration",
            ],
        },
        "recommended_actions": [
            "Enable IMDSv2 (require session tokens)",
            "Set hop limit to 1 (prevent container access)",
            "Use VPC endpoints for AWS services instead of IMDS",
            "Implement network segmentation for IMDS endpoint",
        ],
    }

    # Apply risk score adjustment
    if "risk_score" in finding:
        has_critical = any(f["remediation_priority"] == "critical" for f in factors)
        score_delta = 20.0 if has_critical else 10.0

        original_score = finding["risk_score"]
        finding["risk_score"] = min(100.0, original_score + score_delta)
        result["risk_score_delta"] = score_delta
        result["original_risk_score"] = original_score
        result["adjusted_risk_score"] = finding["risk_score"]

        # Upgrade severity for SSRF to IMDS
        if "ssrf_to_imds" in {f["factor_id"] for f in factors}:
            if finding.get("severity") != "critical":
                result["severity_upgraded"] = True
                result["original_severity"] = finding.get("severity")
                finding["severity"] = "critical"

    logger.info(
        f"IMDS enrichment: {len(factors)} risk factor(s), "
        f"{len(remediation_commands)} remediation command(s)"
    )

    return result


__all__ = ["enrich_with_imds_context"]
