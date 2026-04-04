#!/usr/bin/env python3
"""Merge findings from multiple sources"""

import logging

logger = logging.getLogger(__name__)


def merge_findings(scoutsuite_findings, prowler_findings):
    """Merge and deduplicate findings from different tools"""
    merged = {}

    # Process ScoutSuite findings
    for i, finding in enumerate(scoutsuite_findings):
        resource_id = finding.get('resource_id') or f"_unknown_ss_{i}"
        finding_type = finding.get('type') or 'unknown'
        key = f"{resource_id}_{finding_type}"
        merged[key] = finding

    # Process Prowler findings
    for i, finding in enumerate(prowler_findings):
        resource_id = finding.get('resource_id') or f"_unknown_pr_{i}"
        check_id = finding.get('check_id') or 'unknown'
        key = f"{resource_id}_{check_id}"
        if key not in merged:
            merged[key] = finding

    return list(merged.values())


if __name__ == "__main__":
    logger.info("Merge findings utility")
