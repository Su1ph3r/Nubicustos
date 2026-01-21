"""
Security Enrichment Pipeline for Nubicustos.

This module orchestrates multiple security enrichers that add context to findings:
- CISA KEV (Known Exploited Vulnerabilities) cross-referencing
- Kubernetes CVE version checking
- Container escape risk scoring
- IMDS context enrichment

All enrichments are additive and non-breaking. Failures are logged but don't
stop report processing.

Usage:
    from enrichments import apply_security_enrichments

    for finding in findings:
        apply_security_enrichments(finding)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Import enrichers with graceful fallback
_enrichers_available = True

try:
    from .cisa_kev_provider import enrich_with_cisa_kev
    from .container_escape_scorer import enrich_with_container_escape_risk
    from .k8s_cve_checker import enrich_with_k8s_cve
    from .imds_enricher import enrich_with_imds_context
except ImportError as e:
    logger.warning(f"Some enrichers not available: {e}")
    _enrichers_available = False


def apply_security_enrichments(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Apply all security enrichments to a finding.

    This function orchestrates multiple enrichers, each adding data to
    the finding's threat_intel_enrichment field. Each enricher is wrapped
    in try/except to ensure failures don't break processing.

    Args:
        finding: The finding dictionary to enrich

    Returns:
        The enriched finding dictionary (modified in place)
    """
    if not _enrichers_available:
        return finding

    # Initialize threat_intel_enrichment if not present
    if finding.get("threat_intel_enrichment") is None:
        finding["threat_intel_enrichment"] = {}

    # Apply each enricher with error handling
    enrichers = [
        ("cisa_kev", enrich_with_cisa_kev),
        ("k8s_cve", enrich_with_k8s_cve),
        ("container_escape_risk", enrich_with_container_escape_risk),
        ("imds_context", enrich_with_imds_context),
    ]

    for enricher_name, enricher_func in enrichers:
        try:
            result = enricher_func(finding)
            if result:
                finding["threat_intel_enrichment"][enricher_name] = result
                logger.debug(f"Applied {enricher_name} enrichment to finding")
        except Exception as e:
            logger.warning(f"Enricher {enricher_name} failed: {e}")
            # Continue with other enrichers

    return finding


def apply_single_enrichment(
    finding: dict[str, Any], enricher_name: str
) -> dict[str, Any] | None:
    """
    Apply a single enricher to a finding.

    Args:
        finding: The finding dictionary
        enricher_name: Name of the enricher (cisa_kev, k8s_cve,
                       container_escape_risk, imds_context)

    Returns:
        The enrichment result dict or None if not applicable/failed
    """
    if not _enrichers_available:
        return None

    enricher_map = {
        "cisa_kev": enrich_with_cisa_kev,
        "k8s_cve": enrich_with_k8s_cve,
        "container_escape_risk": enrich_with_container_escape_risk,
        "imds_context": enrich_with_imds_context,
    }

    enricher_func = enricher_map.get(enricher_name)
    if not enricher_func:
        logger.warning(f"Unknown enricher: {enricher_name}")
        return None

    try:
        return enricher_func(finding)
    except Exception as e:
        logger.warning(f"Enricher {enricher_name} failed: {e}")
        return None


__all__ = [
    "apply_security_enrichments",
    "apply_single_enrichment",
]
