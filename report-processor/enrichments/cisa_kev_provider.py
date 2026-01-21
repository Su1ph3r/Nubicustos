"""
CISA Known Exploited Vulnerabilities (KEV) Enrichment Provider.

This module cross-references findings with the CISA KEV catalog to identify
vulnerabilities that are known to be actively exploited in the wild.

Features:
- Fetches CISA KEV catalog from official JSON feed
- 24-hour local cache to reduce API calls
- CVE ID extraction from finding text using regex
- Risk score adjustment for KEV matches
- Extra penalty for ransomware-associated CVEs

Data Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Storage: finding["threat_intel_enrichment"]["cisa_kev"]
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

# CISA KEV catalog URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache settings
CACHE_FILE = "/tmp/cisa_kev_cache.json"
CACHE_TTL_HOURS = 24

# Risk score adjustments
KEV_BASE_SCORE_DELTA = 15.0  # Base score increase for KEV match
KEV_RANSOMWARE_SCORE_DELTA = 25.0  # Score increase if ransomware-associated

# Regex pattern for CVE IDs
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _load_kev_catalog() -> dict[str, Any] | None:
    """
    Load the CISA KEV catalog, using cache if valid.

    Returns:
        The KEV catalog dict or None if unavailable
    """
    # Check cache first
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                cache_data = json.load(f)

            cache_time = datetime.fromisoformat(cache_data.get("cached_at", ""))
            if datetime.utcnow() - cache_time < timedelta(hours=CACHE_TTL_HOURS):
                logger.debug("Using cached CISA KEV catalog")
                return cache_data.get("catalog")
        except (json.JSONDecodeError, ValueError, OSError) as e:
            logger.debug(f"Cache invalid or expired: {e}")

    # Fetch fresh catalog
    try:
        import requests

        logger.info("Fetching CISA KEV catalog from official feed")
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        catalog = response.json()

        # Cache the result
        cache_data = {
            "cached_at": datetime.utcnow().isoformat(),
            "catalog": catalog,
        }
        with open(CACHE_FILE, "w") as f:
            json.dump(cache_data, f)

        logger.info(
            f"Cached CISA KEV catalog with {len(catalog.get('vulnerabilities', []))} entries"
        )
        return catalog

    except Exception as e:
        logger.warning(f"Failed to fetch CISA KEV catalog: {e}")
        return None


def _build_kev_lookup(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Build a lookup dictionary from the KEV catalog.

    Args:
        catalog: The raw KEV catalog

    Returns:
        Dict mapping CVE ID to vulnerability details
    """
    lookup = {}
    for vuln in catalog.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "").upper()
        if cve_id:
            lookup[cve_id] = {
                "cve_id": cve_id,
                "vendor_project": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "vulnerability_name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "short_description": vuln.get("shortDescription", ""),
                "required_action": vuln.get("requiredAction", ""),
                "due_date": vuln.get("dueDate", ""),
                "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown")
                == "Known",
                "notes": vuln.get("notes", ""),
            }
    return lookup


def _extract_cve_ids(finding: dict[str, Any]) -> list[str]:
    """
    Extract CVE IDs from a finding.

    Args:
        finding: The finding dictionary

    Returns:
        List of unique CVE IDs found in the finding
    """
    # Fields to search for CVE IDs
    search_fields = [
        finding.get("check_title", ""),
        finding.get("title", ""),
        finding.get("check_id", ""),
        finding.get("description", ""),
        finding.get("poc_evidence", ""),
        finding.get("resource_details", ""),
    ]

    # Include any nested CVE fields
    if "cve" in finding:
        cve_field = finding["cve"]
        if isinstance(cve_field, str):
            search_fields.append(cve_field)
        elif isinstance(cve_field, list):
            search_fields.extend(str(c) for c in cve_field)

    # Combine and search
    combined_text = " ".join(str(f) for f in search_fields if f)
    cve_ids = CVE_PATTERN.findall(combined_text)

    # Normalize and deduplicate
    return list(set(cve.upper() for cve in cve_ids))


def enrich_with_cisa_kev(finding: dict[str, Any]) -> dict[str, Any] | None:
    """
    Enrich a finding with CISA KEV data.

    Args:
        finding: The finding dictionary

    Returns:
        Enrichment result dict or None if no KEV matches
    """
    # Extract CVE IDs from finding
    cve_ids = _extract_cve_ids(finding)
    if not cve_ids:
        return None

    # Load KEV catalog
    catalog = _load_kev_catalog()
    if not catalog:
        return None

    # Build lookup
    kev_lookup = _build_kev_lookup(catalog)

    # Check for matches
    kev_matches = []
    has_ransomware_association = False
    highest_score_delta = 0.0

    for cve_id in cve_ids:
        if cve_id in kev_lookup:
            match = kev_lookup[cve_id]
            kev_matches.append(match)

            if match["known_ransomware_use"]:
                has_ransomware_association = True
                highest_score_delta = max(highest_score_delta, KEV_RANSOMWARE_SCORE_DELTA)
            else:
                highest_score_delta = max(highest_score_delta, KEV_BASE_SCORE_DELTA)

    if not kev_matches:
        return None

    # Build enrichment result
    result = {
        "is_in_kev": True,
        "kev_matches": kev_matches,
        "cves_checked": cve_ids,
        "total_matches": len(kev_matches),
        "has_ransomware_association": has_ransomware_association,
        "risk_score_delta": highest_score_delta,
        "catalog_date": catalog.get("catalogVersion", ""),
        "enrichment_timestamp": datetime.utcnow().isoformat(),
    }

    # Apply risk score adjustment to finding
    if "risk_score" in finding:
        original_score = finding["risk_score"]
        finding["risk_score"] = min(100.0, original_score + highest_score_delta)
        result["original_risk_score"] = original_score
        result["adjusted_risk_score"] = finding["risk_score"]

        # Potentially upgrade severity
        if finding["risk_score"] >= 90 and finding.get("severity") != "critical":
            result["severity_upgraded"] = True
            result["original_severity"] = finding.get("severity")
            finding["severity"] = "critical"

    logger.info(
        f"Found {len(kev_matches)} CISA KEV match(es) for finding "
        f"(ransomware: {has_ransomware_association})"
    )

    return result


__all__ = ["enrich_with_cisa_kev"]
