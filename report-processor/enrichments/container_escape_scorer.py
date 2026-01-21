"""
Container Escape Risk Scoring Module.

This module evaluates container configurations for escape risk based on
dangerous privileges, capabilities, host namespace sharing, and sensitive mounts.

Each risk factor includes MITRE ATT&CK technique IDs for reference.

Risk factors evaluated:
- Privileged mode
- Dangerous capabilities (SYS_ADMIN, SYS_PTRACE, DAC_OVERRIDE, etc.)
- Host namespace sharing (PID, network, IPC)
- Sensitive mount paths (/var/run/docker.sock, /etc, /root, etc.)
- Security context misconfigurations

Storage: finding["threat_intel_enrichment"]["container_escape_risk"]
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Risk factor definitions with scores and MITRE ATT&CK mappings
CONTAINER_RISK_FACTORS = {
    # Privileged mode - highest risk
    "privileged": {
        "score": 40,
        "mitre_technique": "T1611",
        "mitre_name": "Escape to Host",
        "description": "Container running in privileged mode can escape to host",
        "keywords": ["privileged", "privileged:true", "privileged mode"],
    },
    # Dangerous capabilities
    "cap_sys_admin": {
        "score": 35,
        "mitre_technique": "T1611",
        "mitre_name": "Escape to Host",
        "description": "SYS_ADMIN capability allows mount operations and namespace manipulation",
        "keywords": ["sys_admin", "cap_sys_admin", "sys-admin"],
    },
    "cap_sys_ptrace": {
        "score": 30,
        "mitre_technique": "T1055",
        "mitre_name": "Process Injection",
        "description": "SYS_PTRACE allows debugging/tracing other processes",
        "keywords": ["sys_ptrace", "cap_sys_ptrace", "sys-ptrace", "ptrace"],
    },
    "cap_dac_override": {
        "score": 25,
        "mitre_technique": "T1222",
        "mitre_name": "File and Directory Permissions Modification",
        "description": "DAC_OVERRIDE bypasses file permission checks",
        "keywords": ["dac_override", "cap_dac_override", "dac-override"],
    },
    "cap_net_admin": {
        "score": 20,
        "mitre_technique": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "NET_ADMIN allows network configuration manipulation",
        "keywords": ["net_admin", "cap_net_admin", "net-admin"],
    },
    "cap_net_raw": {
        "score": 15,
        "mitre_technique": "T1040",
        "mitre_name": "Network Sniffing",
        "description": "NET_RAW allows raw socket operations for packet capture",
        "keywords": ["net_raw", "cap_net_raw", "net-raw"],
    },
    "cap_setuid": {
        "score": 20,
        "mitre_technique": "T1548.001",
        "mitre_name": "Setuid and Setgid",
        "description": "SETUID/SETGID allows arbitrary UID/GID changes",
        "keywords": ["setuid", "cap_setuid", "setgid", "cap_setgid"],
    },
    # Host namespace sharing
    "host_pid_namespace": {
        "score": 30,
        "mitre_technique": "T1611",
        "mitre_name": "Escape to Host",
        "description": "Host PID namespace exposes all host processes",
        "keywords": ["hostpid", "host_pid", "pidmode:host", "pid=host", "host pid"],
    },
    "host_network_namespace": {
        "score": 25,
        "mitre_technique": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "Host network namespace allows host network access",
        "keywords": ["hostnetwork", "host_network", "networkmode:host", "network=host", "host network"],
    },
    "host_ipc_namespace": {
        "score": 20,
        "mitre_technique": "T1559",
        "mitre_name": "Inter-Process Communication",
        "description": "Host IPC namespace allows shared memory access with host",
        "keywords": ["hostipc", "host_ipc", "ipcmode:host", "ipc=host", "host ipc"],
    },
    # Sensitive mount paths
    "docker_socket_mount": {
        "score": 40,
        "mitre_technique": "T1611",
        "mitre_name": "Escape to Host",
        "description": "Docker socket mount allows full Docker daemon control",
        "keywords": ["/var/run/docker.sock", "docker.sock", "/var/run/docker"],
    },
    "host_etc_mount": {
        "score": 30,
        "mitre_technique": "T1552.001",
        "mitre_name": "Credentials In Files",
        "description": "Host /etc mount exposes system configuration and credentials",
        "keywords": [":/etc:", ":/etc ", "mount /etc", "hostpath: /etc"],
    },
    "host_root_mount": {
        "score": 35,
        "mitre_technique": "T1552.001",
        "mitre_name": "Credentials In Files",
        "description": "Host root mount exposes entire filesystem",
        "keywords": [":/:/", ":/ ", "hostpath: /", "mount /"],
    },
    "host_proc_mount": {
        "score": 30,
        "mitre_technique": "T1082",
        "mitre_name": "System Information Discovery",
        "description": "Host /proc mount exposes process information",
        "keywords": [":/proc:", ":/proc ", "hostpath: /proc"],
    },
    "host_sys_mount": {
        "score": 25,
        "mitre_technique": "T1082",
        "mitre_name": "System Information Discovery",
        "description": "Host /sys mount exposes kernel parameters",
        "keywords": [":/sys:", ":/sys ", "hostpath: /sys"],
    },
    # Security context issues
    "run_as_root": {
        "score": 15,
        "mitre_technique": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation",
        "description": "Container running as root user",
        "keywords": ["runasuser: 0", "user: root", "uid=0", "root user", "running as root"],
    },
    "no_seccomp": {
        "score": 15,
        "mitre_technique": "T1611",
        "mitre_name": "Escape to Host",
        "description": "Seccomp profile disabled or set to unconfined",
        "keywords": ["seccomp:unconfined", "seccompprofile:unconfined", "seccomp=unconfined", "no seccomp"],
    },
    "no_apparmor": {
        "score": 10,
        "mitre_technique": "T1562.001",
        "mitre_name": "Impair Defenses",
        "description": "AppArmor profile disabled",
        "keywords": ["apparmor:unconfined", "apparmor=unconfined", "no apparmor"],
    },
    "allow_privilege_escalation": {
        "score": 20,
        "mitre_technique": "T1548",
        "mitre_name": "Abuse Elevation Control Mechanism",
        "description": "allowPrivilegeEscalation set to true",
        "keywords": ["allowprivilegeescalation:true", "allowprivilegeescalation: true", "privilege escalation"],
    },
}

# Risk level thresholds
RISK_LEVELS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
    "low": 10,
}


def _is_container_finding(finding: dict[str, Any]) -> bool:
    """
    Check if a finding is related to containers or Kubernetes.

    Args:
        finding: The finding dictionary

    Returns:
        True if container-related
    """
    container_indicators = [
        "container",
        "docker",
        "kubernetes",
        "k8s",
        "pod",
        "deployment",
        "daemonset",
        "statefulset",
        "replicaset",
        "ecs",
        "fargate",
        "eks",
        "aks",
        "gke",
    ]

    # Check relevant fields
    check_fields = [
        finding.get("check_title", ""),
        finding.get("title", ""),
        finding.get("check_id", ""),
        finding.get("service", ""),
        finding.get("resource_type", ""),
        finding.get("description", ""),
    ]

    combined = " ".join(str(f).lower() for f in check_fields if f)

    return any(indicator in combined for indicator in container_indicators)


def _detect_risk_factors(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Detect container escape risk factors in a finding.

    Args:
        finding: The finding dictionary

    Returns:
        List of detected risk factors with details
    """
    detected_factors = []

    # Build searchable text from finding
    search_fields = [
        finding.get("check_title", ""),
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("poc_evidence", ""),
        finding.get("resource_details", ""),
        finding.get("remediation", ""),
    ]

    # Include resource config if present
    resource_config = finding.get("resource_config", {})
    if isinstance(resource_config, dict):
        search_fields.append(str(resource_config))

    combined_text = " ".join(str(f).lower() for f in search_fields if f)

    # Check each risk factor
    for factor_id, factor_info in CONTAINER_RISK_FACTORS.items():
        for keyword in factor_info["keywords"]:
            if keyword.lower() in combined_text:
                detected_factors.append({
                    "factor_id": factor_id,
                    "score": factor_info["score"],
                    "mitre_technique": factor_info["mitre_technique"],
                    "mitre_name": factor_info["mitre_name"],
                    "description": factor_info["description"],
                    "matched_keyword": keyword,
                })
                break  # Only count each factor once

    return detected_factors


def _calculate_risk_level(total_score: int) -> str:
    """
    Determine risk level from total score.

    Args:
        total_score: Cumulative risk score

    Returns:
        Risk level string (critical, high, medium, low, info)
    """
    if total_score >= RISK_LEVELS["critical"]:
        return "critical"
    elif total_score >= RISK_LEVELS["high"]:
        return "high"
    elif total_score >= RISK_LEVELS["medium"]:
        return "medium"
    elif total_score >= RISK_LEVELS["low"]:
        return "low"
    else:
        return "info"


def enrich_with_container_escape_risk(finding: dict[str, Any]) -> dict[str, Any] | None:
    """
    Enrich a finding with container escape risk assessment.

    Args:
        finding: The finding dictionary

    Returns:
        Enrichment result dict or None if not container-related
    """
    # Only process container-related findings
    if not _is_container_finding(finding):
        return None

    # Detect risk factors
    factors = _detect_risk_factors(finding)

    if not factors:
        return None

    # Calculate total score (capped at 100)
    total_score = min(100, sum(f["score"] for f in factors))
    risk_level = _calculate_risk_level(total_score)

    # Collect unique MITRE techniques
    mitre_techniques = list(set(
        f"{f['mitre_technique']} ({f['mitre_name']})" for f in factors
    ))

    # Build result
    result = {
        "total_score": total_score,
        "risk_level": risk_level,
        "factors": factors,
        "factor_count": len(factors),
        "mitre_techniques": mitre_techniques,
        "assessment_details": {
            "has_privileged": any(f["factor_id"] == "privileged" for f in factors),
            "has_docker_socket": any(f["factor_id"] == "docker_socket_mount" for f in factors),
            "has_dangerous_caps": any(
                f["factor_id"].startswith("cap_") for f in factors
            ),
            "has_host_namespace": any(
                "namespace" in f["factor_id"] for f in factors
            ),
            "has_sensitive_mounts": any(
                "mount" in f["factor_id"] for f in factors
            ),
        },
    }

    # Apply risk score adjustment
    if "risk_score" in finding and total_score >= 30:
        # Add 10-30 points based on escape risk level
        score_boost = min(30, total_score // 3)
        original_score = finding["risk_score"]
        finding["risk_score"] = min(100.0, original_score + score_boost)
        result["risk_score_delta"] = score_boost
        result["original_risk_score"] = original_score
        result["adjusted_risk_score"] = finding["risk_score"]

        # Potentially upgrade severity
        if risk_level == "critical" and finding.get("severity") not in ["critical"]:
            result["severity_upgraded"] = True
            result["original_severity"] = finding.get("severity")
            finding["severity"] = "critical"
        elif risk_level == "high" and finding.get("severity") in ["medium", "low", "info"]:
            result["severity_upgraded"] = True
            result["original_severity"] = finding.get("severity")
            finding["severity"] = "high"

    logger.info(
        f"Container escape risk: {risk_level} (score: {total_score}, "
        f"factors: {len(factors)})"
    )

    return result


__all__ = ["enrich_with_container_escape_risk"]
