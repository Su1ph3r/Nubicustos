"""Parser modules for processing security tool reports."""

from .cloud_parsers import (
    process_cloudsploit_report,
    process_prowler_report,
    process_scoutsuite_report,
)
from .iac_parsers import (
    process_checkov_report,
    process_kube_linter_report,
    process_polaris_report,
    process_terrascan_report,
    process_tfsec_report,
)
from .iam_parsers import process_cloudsplaining_report, process_pmapper_report
from .secrets_parsers import process_gitleaks_report, process_trufflehog_report

__all__ = [
    "process_scoutsuite_report",
    "process_prowler_report",
    "process_cloudsploit_report",
    "process_kube_linter_report",
    "process_polaris_report",
    "process_checkov_report",
    "process_terrascan_report",
    "process_tfsec_report",
    "process_trufflehog_report",
    "process_gitleaks_report",
    "process_pmapper_report",
    "process_cloudsplaining_report",
]
