"""
Kubernetes CVE Version Checker.

This module checks Kubernetes component versions against known CVEs.
It maintains a local database of K8s-specific CVEs with affected version ranges.

CVEs tracked:
- CVE-2024-10220: Git-sync vulnerability (kubelet)
- CVE-2025-1974: IngressNightmare controller RCE
- CVE-2025-4563: Kubernetes API server auth bypass
- CVE-2025-23266: Container runtime privilege escalation

Storage: finding["threat_intel_enrichment"]["k8s_cve"]
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Try to import semver, fall back to simple comparison
try:
    import semver

    SEMVER_AVAILABLE = True
except ImportError:
    SEMVER_AVAILABLE = False
    logger.warning("semver library not available, using basic version comparison")


# K8s CVE Database with affected version ranges
K8S_CVE_DATABASE = {
    "CVE-2024-10220": {
        "title": "Git-sync arbitrary file read vulnerability",
        "component": "kubelet",
        "severity": "high",
        "cvss_score": 8.1,
        "affected_versions": {
            "min": "1.25.0",
            "max": "1.29.10",
            "fixed_in": ["1.29.11", "1.30.7", "1.31.3"],
        },
        "description": "Allows reading arbitrary files from the host filesystem via gitRepo volume",
        "references": [
            "https://github.com/kubernetes/kubernetes/issues/128885",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10220",
        ],
        "mitre_technique": "T1083",
        "keywords": ["gitrepo", "git-sync", "kubelet"],
    },
    "CVE-2025-1974": {
        "title": "IngressNightmare - Ingress NGINX Controller RCE",
        "component": "ingress-nginx",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_versions": {
            "min": "0.0.0",
            "max": "1.12.0",
            "fixed_in": ["1.12.1", "1.11.5"],
        },
        "description": "Remote code execution via admission controller webhook bypass",
        "references": [
            "https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/",
        ],
        "mitre_technique": "T1190",
        "keywords": ["ingress-nginx", "ingress nginx", "ingressnightmare"],
    },
    "CVE-2025-4563": {
        "title": "Kubernetes API Server Authentication Bypass",
        "component": "kube-apiserver",
        "severity": "critical",
        "cvss_score": 9.1,
        "affected_versions": {
            "min": "1.28.0",
            "max": "1.29.8",
            "fixed_in": ["1.29.9", "1.30.5", "1.31.1"],
        },
        "description": "Authentication bypass in API server allows unauthorized cluster access",
        "references": [],
        "mitre_technique": "T1078",
        "keywords": ["kube-apiserver", "api server", "apiserver", "authentication"],
    },
    "CVE-2025-23266": {
        "title": "Container Runtime Privilege Escalation",
        "component": "containerd",
        "severity": "high",
        "cvss_score": 8.8,
        "affected_versions": {
            "min": "1.6.0",
            "max": "1.7.20",
            "fixed_in": ["1.7.21", "2.0.0"],
        },
        "description": "Container escape via runtime vulnerability allowing host root access",
        "references": [],
        "mitre_technique": "T1611",
        "keywords": ["containerd", "container runtime", "runc"],
    },
    "CVE-2024-21626": {
        "title": "runc container breakout (Leaky Vessels)",
        "component": "runc",
        "severity": "critical",
        "cvss_score": 8.6,
        "affected_versions": {
            "min": "0.0.0",
            "max": "1.1.11",
            "fixed_in": ["1.1.12"],
        },
        "description": "Process.cwd and leaked fds container escape (Leaky Vessels)",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
        ],
        "mitre_technique": "T1611",
        "keywords": ["runc", "leaky vessels", "process.cwd"],
    },
}


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """
    Parse a version string into a tuple for comparison.

    Args:
        version_str: Version string like "1.29.5" or "v1.29.5"

    Returns:
        Tuple of version numbers or None if unparseable
    """
    # Remove 'v' prefix if present
    clean_version = version_str.lower().lstrip("v")

    # Extract just the version numbers (handle suffixes like -eks, -gke, etc.)
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", clean_version)
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0

    return (major, minor, patch)


def _version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """
    Check if a version falls within a vulnerable range.

    Args:
        version: Version to check
        min_ver: Minimum affected version
        max_ver: Maximum affected version

    Returns:
        True if version is in the affected range
    """
    if SEMVER_AVAILABLE:
        try:
            # Normalize versions for semver
            v = semver.Version.parse(version.lstrip("v").split("-")[0])
            min_v = semver.Version.parse(min_ver)
            max_v = semver.Version.parse(max_ver)
            return min_v <= v <= max_v
        except ValueError:
            pass

    # Fallback to tuple comparison
    v = _parse_version(version)
    min_v = _parse_version(min_ver)
    max_v = _parse_version(max_ver)

    if not all([v, min_v, max_v]):
        return False

    return min_v <= v <= max_v


def _is_version_fixed(version: str, fixed_versions: list[str]) -> bool:
    """
    Check if a version is at or above a fixed version.

    Args:
        version: Version to check
        fixed_versions: List of fixed version strings

    Returns:
        True if version is fixed
    """
    v = _parse_version(version)
    if not v:
        return False

    for fixed in fixed_versions:
        fixed_v = _parse_version(fixed)
        if fixed_v and v >= fixed_v:
            # Check if same major.minor line
            if v[0] == fixed_v[0] and v[1] == fixed_v[1]:
                return True

    return False


def _is_k8s_finding(finding: dict[str, Any]) -> bool:
    """
    Check if a finding is Kubernetes-related.

    Args:
        finding: The finding dictionary

    Returns:
        True if K8s-related
    """
    k8s_indicators = [
        "kubernetes",
        "k8s",
        "kubelet",
        "kube-apiserver",
        "kube-controller",
        "kube-scheduler",
        "kubectl",
        "eks",
        "aks",
        "gke",
        "pod",
        "deployment",
        "statefulset",
        "daemonset",
        "ingress",
        "containerd",
        "runc",
    ]

    check_fields = [
        finding.get("check_title", ""),
        finding.get("title", ""),
        finding.get("check_id", ""),
        finding.get("service", ""),
        finding.get("description", ""),
    ]

    combined = " ".join(str(f).lower() for f in check_fields if f)

    return any(indicator in combined for indicator in k8s_indicators)


def _extract_k8s_versions(finding: dict[str, Any]) -> list[dict[str, str]]:
    """
    Extract Kubernetes component versions from a finding.

    Args:
        finding: The finding dictionary

    Returns:
        List of dicts with 'component' and 'version' keys
    """
    versions = []

    # Version pattern: looks for patterns like "kubelet 1.29.5" or "version: v1.28.0"
    version_patterns = [
        r"(kubelet)[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"(kube-apiserver)[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"(ingress-nginx)[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"(containerd)[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"(runc)[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"kubernetes[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"server\s+version[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
        r"client\s+version[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
    ]

    search_fields = [
        finding.get("description", ""),
        finding.get("poc_evidence", ""),
        finding.get("resource_details", ""),
        finding.get("resource_config", ""),
    ]

    combined_text = " ".join(str(f).lower() for f in search_fields if f)

    for pattern in version_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple) and len(match) == 2:
                versions.append({
                    "component": match[0].lower(),
                    "version": match[1],
                })
            elif isinstance(match, str):
                # Generic kubernetes version
                versions.append({
                    "component": "kubernetes",
                    "version": match,
                })

    return versions


def _check_cve_matches(
    component: str, version: str
) -> list[dict[str, Any]]:
    """
    Check if a component version matches any known CVEs.

    Args:
        component: Component name
        version: Version string

    Returns:
        List of matching CVE details
    """
    matches = []

    for cve_id, cve_info in K8S_CVE_DATABASE.items():
        # Check if component matches
        cve_component = cve_info["component"].lower()
        if component.lower() not in [cve_component] and cve_component not in component.lower():
            # Also check keywords
            keywords_match = any(
                kw in component.lower() for kw in cve_info.get("keywords", [])
            )
            if not keywords_match:
                continue

        # Check version range
        affected = cve_info["affected_versions"]
        if _version_in_range(version, affected["min"], affected["max"]):
            # Check if already fixed
            if _is_version_fixed(version, affected.get("fixed_in", [])):
                continue

            matches.append({
                "cve_id": cve_id,
                "title": cve_info["title"],
                "severity": cve_info["severity"],
                "cvss_score": cve_info["cvss_score"],
                "description": cve_info["description"],
                "fixed_in": affected.get("fixed_in", []),
                "mitre_technique": cve_info.get("mitre_technique", ""),
                "references": cve_info.get("references", []),
            })

    return matches


def enrich_with_k8s_cve(finding: dict[str, Any]) -> dict[str, Any] | None:
    """
    Enrich a finding with Kubernetes CVE data.

    Args:
        finding: The finding dictionary

    Returns:
        Enrichment result dict or None if no K8s CVE matches
    """
    # Only process K8s-related findings
    if not _is_k8s_finding(finding):
        return None

    # Extract component versions
    component_versions = _extract_k8s_versions(finding)

    if not component_versions:
        # No versions found - check if finding text matches CVE keywords
        check_text = " ".join([
            str(finding.get("check_title", "")),
            str(finding.get("description", "")),
        ]).lower()

        for cve_id, cve_info in K8S_CVE_DATABASE.items():
            if any(kw.lower() in check_text for kw in cve_info.get("keywords", [])):
                # Potential match based on keywords only
                return {
                    "components_checked": [],
                    "potential_cves": [{
                        "cve_id": cve_id,
                        "title": cve_info["title"],
                        "severity": cve_info["severity"],
                        "reason": "keyword_match",
                        "note": "Version not detected - verify manually",
                    }],
                    "version_detection_failed": True,
                }
        return None

    # Check each component for CVE matches
    all_matches = []
    checked_components = []

    for cv in component_versions:
        component = cv["component"]
        version = cv["version"]

        matches = _check_cve_matches(component, version)

        checked_components.append({
            "component": component,
            "version": version,
            "cves_found": len(matches),
            "cves": [m["cve_id"] for m in matches],
        })

        all_matches.extend(matches)

    if not all_matches:
        return None

    # Calculate risk score impact
    max_cvss = max(m["cvss_score"] for m in all_matches)
    has_critical = any(m["severity"] == "critical" for m in all_matches)
    has_high = any(m["severity"] == "high" for m in all_matches)

    # Build result
    result = {
        "components_checked": checked_components,
        "cve_matches": all_matches,
        "total_cves_found": len(all_matches),
        "max_cvss_score": max_cvss,
        "has_critical_cve": has_critical,
        "has_high_cve": has_high,
        "mitre_techniques": list(set(
            m["mitre_technique"] for m in all_matches if m.get("mitre_technique")
        )),
    }

    # Apply risk score adjustment
    if "risk_score" in finding:
        # CVEs warrant significant score increases
        score_delta = 0.0
        if has_critical:
            score_delta = 30.0
        elif has_high:
            score_delta = 20.0
        else:
            score_delta = 10.0

        original_score = finding["risk_score"]
        finding["risk_score"] = min(100.0, original_score + score_delta)
        result["risk_score_delta"] = score_delta
        result["original_risk_score"] = original_score
        result["adjusted_risk_score"] = finding["risk_score"]

        # Upgrade severity for critical CVEs
        if has_critical and finding.get("severity") != "critical":
            result["severity_upgraded"] = True
            result["original_severity"] = finding.get("severity")
            finding["severity"] = "critical"

    logger.info(
        f"Found {len(all_matches)} K8s CVE(s) affecting {len(checked_components)} component(s)"
    )

    return result


__all__ = ["enrich_with_k8s_cve"]
