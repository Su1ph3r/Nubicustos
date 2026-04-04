"""Shared helper functions and constants used by parser modules."""

import hashlib
import json
import logging
import re
import shlex
import subprocess

# Import remediation knowledge base
try:
    from remediation_kb import (
        get_default_description,
        get_default_remediation,
        get_poc_command,
        get_remediation,
    )
except ImportError:
    # Fallback if KB not available
    def get_remediation(ft, ci):
        return None

    def get_poc_command(ft, ci, ri=None):
        return None

    def get_default_remediation(s, d, cloud_provider="aws"):
        return "Review and remediate according to security best practices."

    def get_default_description(s, c, d, cloud_provider="aws"):
        return d or "Security finding detected."


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Class-level constants (moved from ReportProcessor)
# ---------------------------------------------------------------------------

# Generic resource names that should not be used as titles
GENERIC_RESOURCE_NAMES = {
    "notconfigured",
    "not_configured",
    "unknown",
    "n/a",
    "na",
    "none",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "true",
    "false",
    "null",
    "undefined",
}

# AWS resource ID validation pattern
AWS_RESOURCE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9\-\_:/.@]+$")

# Service name normalization mapping (tool-specific -> KB normalized)
SERVICE_NORMALIZATION = {
    # Prowler AWS resource types
    "awscloudtrailtrail": "cloudtrail",
    "awslambdafunction": "lambda",
    "awsec2securitygroup": "security-group",
    "awsec2instance": "ec2",
    "awsec2vpc": "vpc",
    "awss3bucket": "s3",
    "awsiamuser": "iam",
    "awsiamrole": "iam",
    "awsiampolicy": "iam",
    "awsrdsdbinstance": "rds",
    "awsebsvolume": "ebs",
    "awskmskey": "kms",
    "awssqsqueue": "sqs",
    "awssnssubscription": "sns",
    "awsaccount": "iam",
    # CloudSploit categories
    "cloudtrail": "cloudtrail",
    "ec2": "ec2",
    "s3": "s3",
    "iam": "iam",
    "rds": "rds",
    "lambda": "lambda",
    "vpc": "vpc",
    "kms": "kms",
    "sqs": "sqs",
    "sns": "sns",
    "ebs": "ebs",
    "elb": "elb",
    "configservice": "config",
    "securitygroup": "security-group",
}

# Check ID patterns to KB check mappings
CHECK_ID_PATTERNS = {
    # CloudTrail checks
    r"cloudtrail.*enabled": "not-configured",
    r"cloudtrail.*multi.*region": "not-configured",
    r"cloudtrail.*log.*file.*validation": "no-log-validation",
    r"cloudtrail.*global": "no-global-services-logging",
    r"cloudtrail.*encrypted": "not-encrypted",
    # Security Group checks
    r"security.*group.*open": "opens-all-ports",
    r"security.*group.*ssh": "ssh-open",
    r"security.*group.*rdp": "rdp-open",
    r"default.*security.*group": "default-rules",
    # IAM checks
    r"password.*policy": "weak-password-policy",
    r"root.*account": "root-account-used",
    r"mfa": "no-mfa",
    r"access.*key.*rotation": "old-access-keys",
    # S3 checks
    r"bucket.*public": "public-access",
    r"bucket.*encrypt": "not-encrypted",
    r"bucket.*logging": "no-logging",
    r"bucket.*versioning": "no-versioning",
    # RDS checks
    r"rds.*public": "publicly-accessible",
    r"rds.*encrypt": "not-encrypted",
    r"rds.*backup": "no-backups",
    # EBS checks
    r"ebs.*encrypt": "not-encrypted",
    # Lambda checks
    r"lambda.*public": "public-access",
    r"lambda.*secret": "secrets-in-env",
    # KMS checks
    r"kms.*rotation": "no-rotation",
}


# ---------------------------------------------------------------------------
# Helper functions (moved from ReportProcessor instance methods)
# ---------------------------------------------------------------------------

def strip_html_tags(text: str | None) -> str | None:
    """Strip HTML tags from text while preserving content."""
    if not text or not isinstance(text, str):
        return text
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


def is_generic_name(name):
    """Check if a name is generic/placeholder and shouldn't be used as title."""
    if not name:
        return True
    return name.lower().strip() in GENERIC_RESOURCE_NAMES


def normalize_service(resource_type):
    """Normalize resource type to KB service name."""
    if not resource_type:
        return "aws"
    normalized = resource_type.lower().replace(" ", "").replace("-", "").replace("_", "")
    return SERVICE_NORMALIZATION.get(normalized, resource_type.lower().replace(" ", "-"))


def normalize_check_id(check_id, title=""):
    """Normalize check ID to KB check name using pattern matching."""
    if not check_id:
        return ""
    combined = f"{check_id} {title}".lower()
    for pattern, kb_key in CHECK_ID_PATTERNS.items():
        if re.search(pattern, combined, re.IGNORECASE):
            return kb_key
    return check_id.lower().replace(" ", "-").replace("_", "-")


def validate_resource_id(resource_id: str | None) -> bool:
    """Validate that a resource ID matches expected AWS patterns."""
    if not resource_id:
        return False
    return bool(AWS_RESOURCE_ID_PATTERN.match(resource_id))


def validate_azure_resource_id(resource_id: str | None) -> bool:
    """Validate that a resource ID matches expected Azure patterns."""
    if not resource_id:
        return False
    azure_pattern = re.compile(r"^[a-zA-Z0-9\-_/\.]+$")
    return bool(azure_pattern.match(resource_id))


def _extract_resource_name(arn: str) -> str:
    name = arn.split(":")[-1].split("/")[-1]
    return name.strip()


def generate_generic_poc_command(service, resource_id, finding):
    """Generate a generic AWS CLI verification command based on service type."""
    rid = shlex.quote(resource_id) if resource_id and resource_id != "N/A" else None

    s3_name = _extract_resource_name(resource_id) if resource_id and resource_id != "N/A" else ""
    rds_name = _extract_resource_name(resource_id) if resource_id and resource_id != "N/A" else ""
    lambda_name = _extract_resource_name(resource_id) if resource_id and resource_id != "N/A" else ""

    service_commands = {
        "cloudtrail": "aws cloudtrail describe-trails --output json",
        "security-group": f"aws ec2 describe-security-groups --group-ids {rid} --output json"
        if rid
        else "aws ec2 describe-security-groups --output json",
        "ec2": f"aws ec2 describe-instances --instance-ids {rid} --output json"
        if rid and "i-" in str(resource_id)
        else "aws ec2 describe-instances --output json",
        "s3": f"aws s3api get-bucket-policy --bucket {shlex.quote(s3_name)} --output json"
        if rid and s3_name
        else "aws s3 ls --output json",
        "iam": "aws iam get-account-password-policy --output json",
        "rds": f"aws rds describe-db-instances --db-instance-identifier {shlex.quote(rds_name)} --output json"
        if rid and rds_name
        else "aws rds describe-db-instances --output json",
        "lambda": f"aws lambda get-function --function-name {shlex.quote(lambda_name)} --output json"
        if rid and lambda_name
        else "aws lambda list-functions --output json",
        "kms": "aws kms list-keys --output json",
        "vpc": "aws ec2 describe-vpcs --output json",
        "ebs": "aws ec2 describe-volumes --output json",
        "sqs": "aws sqs list-queues --output json",
        "config": "aws configservice describe-configuration-recorders --output json",
    }

    if service in service_commands:
        cmd = service_commands[service]
        if resource_id and resource_id != "N/A" and validate_resource_id(resource_id):
            return cmd
        base_cmd = service_commands[service]
        if "--group-ids" in base_cmd or "--instance-ids" in base_cmd or "--bucket" in base_cmd:
            return service_commands.get(service, "").split("--")[0].strip() + " --output json"
        return base_cmd

    return None


def generate_azure_poc_command(service, resource_id, finding):
    """Generate an Azure CLI verification command based on service type."""
    service_commands = {
        "storageaccounts": "az storage account list --output json",
        "storage": "az storage account list --output json",
        "virtualmachines": "az vm list --output json",
        "vm": "az vm list --output json",
        "sqldatabases": "az sql db list --output json",
        "sql": "az sql server list --output json",
        "keyvault": "az keyvault list --output json",
        "appservice": "az webapp list --output json",
        "webapp": "az webapp list --output json",
        "networkinterfaces": "az network nic list --output json",
        "nic": "az network nic list --output json",
        "securitygroups": "az network nsg list --output json",
        "nsg": "az network nsg list --output json",
        "virtualnetworks": "az network vnet list --output json",
        "vnet": "az network vnet list --output json",
        "loadbalancers": "az network lb list --output json",
        "lb": "az network lb list --output json",
        "applicationgateways": "az network application-gateway list --output json",
        "appgateway": "az network application-gateway list --output json",
        "cosmosdb": "az cosmosdb list --output json",
        "aks": "az aks list --output json",
        "kubernetes": "az aks list --output json",
        "acr": "az acr list --output json",
        "containerregistry": "az acr list --output json",
        "monitor": "az monitor activity-log list --output json",
        "activitylog": "az monitor activity-log list --output json",
        "defender": "az security pricing list --output json",
        "securitycenter": "az security pricing list --output json",
        "rbac": "az role assignment list --output json",
        "iam": "az role assignment list --output json",
        "policy": "az policy assignment list --output json",
        "resourcegroups": "az group list --output json",
        "rg": "az group list --output json",
        "subscriptions": "az account list --output json",
        "subscription": "az account list --output json",
        "logging": "az monitor diagnostic-settings list --output json",
        "diagnostics": "az monitor diagnostic-settings list --output json",
        "appinsights": "az monitor app-insights component list --output json",
        "applicationinsights": "az monitor app-insights component list --output json",
        "insights": "az monitor app-insights component list --output json",
        "network": "az network nsg list --output json",
        "security": "az security pricing list --output json",
        "alert": "az monitor activity-log alert list --output json",
        "activitylogalert": "az monitor activity-log alert list --output json",
        "logalert": "az monitor activity-log alert list --output json",
        "contact": "az security contact list --output json",
        "securitycontact": "az security contact list --output json",
        "autoprovisioning": "az security auto-provisioning-setting list --output json",
        "provisioning": "az security auto-provisioning-setting list --output json",
        "disk": "az disk list --output json",
        "disks": "az disk list --output json",
        "manageddisk": "az disk list --output json",
        "manageddisks": "az disk list --output json",
        "functionapp": "az functionapp list --output json",
        "function": "az functionapp list --output json",
        "functions": "az functionapp list --output json",
        "logicapp": "az logic workflow list --output json",
        "logic": "az logic workflow list --output json",
        "redis": "az redis list --output json",
        "cache": "az redis list --output json",
        "servicebus": "az servicebus namespace list --output json",
        "eventhub": "az eventhubs namespace list --output json",
        "postgresql": "az postgres server list --output json",
        "postgres": "az postgres server list --output json",
        "mysql": "az mysql server list --output json",
        "mariadb": "az mariadb server list --output json",
    }

    normalized_service = service.lower().replace("-", "").replace("_", "")

    if normalized_service in service_commands:
        return service_commands[normalized_service]

    for key, cmd in service_commands.items():
        if key in normalized_service or normalized_service in key:
            return cmd

    return None


def run_cli_command(command: str | list[str], cli_name: str, timeout: int = 30) -> str:
    """Run a CLI command safely and return the output."""
    try:
        if isinstance(command, str):
            parts = shlex.split(command)
        else:
            parts = list(command)

        if not parts or parts[0] != cli_name:
            logger.warning(f"Invalid {cli_name} CLI command attempted")
            return "Invalid command format"

        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logger.debug(f"{cli_name} CLI command failed: {result.stderr.strip()}")
            return "Command execution failed"
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except FileNotFoundError:
        return f"{cli_name.upper()} CLI not available"
    except (ValueError, OSError) as e:
        logger.error(f"Error running {cli_name} CLI: {str(e)}")
        return "Command execution error"


def run_aws_cli(command: str | list[str]) -> str:
    """Run an AWS CLI command safely and return the output."""
    return run_cli_command(command, "aws")


def run_azure_cli(command: str | list[str]) -> str:
    """Run an Azure CLI command safely and return the output."""
    return run_cli_command(command, "az")


def enhance_finding(finding, service, check_id, cloud_provider="aws"):
    """Enhance a finding with data from remediation KB."""
    normalized_service = normalize_service(service)
    title = finding.get("check_title", finding.get("title", ""))
    normalized_check = normalize_check_id(check_id, title)

    kb_data = get_remediation(normalized_service, normalized_check)
    if not kb_data:
        kb_data = get_remediation(service.lower(), check_id.lower())
    if not kb_data:
        kb_data = get_remediation(normalized_service, check_id.lower())

    current_desc = finding.get("description", "")
    if not current_desc or len(current_desc) < 30 or "no description" in current_desc.lower():
        if kb_data and kb_data.get("description"):
            finding["description"] = kb_data["description"]
        else:
            finding["description"] = get_default_description(
                normalized_service, check_id, current_desc, cloud_provider
            )

    current_remediation = finding.get("remediation", "")
    is_status_message = current_remediation and any(
        x in current_remediation.lower()
        for x in [
            "is not",
            "not enabled",
            "not configured",
            "has default",
            "is publicly",
            "no cloudtrail",
        ]
    )
    if not current_remediation or current_remediation == "N/A" or is_status_message:
        if kb_data and kb_data.get("remediation"):
            finding["remediation"] = kb_data["remediation"]
        else:
            finding["remediation"] = get_default_remediation(
                normalized_service, finding.get("description", ""), cloud_provider
            )

    resource_id = finding.get("resource_id", "")
    poc_command = get_poc_command(normalized_service, normalized_check, resource_id)
    if not poc_command:
        poc_command = get_poc_command(service.lower(), check_id.lower(), resource_id)
    if not poc_command:
        if cloud_provider == "azure":
            poc_command = generate_azure_poc_command(
                normalized_service, resource_id, finding
            )
        else:
            poc_command = generate_generic_poc_command(
                normalized_service, resource_id, finding
            )

    if poc_command:
        finding["poc_verification"] = poc_command

        current_remediation_code = finding.get("remediation_code", {})
        if not isinstance(current_remediation_code, dict):
            current_remediation_code = {}
        cli_key = f"{cloud_provider}_cli"
        if cli_key not in current_remediation_code:
            current_remediation_code[cli_key] = poc_command
            finding["remediation_code"] = current_remediation_code

    if not finding.get("affected_resources") or len(finding.get("affected_resources", [])) == 0:
        affected_resources = []
        if finding.get("resource_id"):
            affected_resources.append(
                {
                    "id": finding.get("resource_id", ""),
                    "name": finding.get("resource_name", finding.get("resource_id", "")),
                    "region": finding.get("region", "global"),
                    "type": finding.get("resource_type", service),
                }
            )
        finding["affected_resources"] = affected_resources
        finding["affected_count"] = len(affected_resources)

    return finding


def build_meaningful_title(service, finding_id, description, resource_name):
    """Build a meaningful title from available data."""
    if description and len(description) > 10 and not is_generic_name(description):
        return description

    title = finding_id.replace("-", " ").replace("_", " ").title()

    service_name = service.replace("-", " ").replace("_", " ").title()
    if service_name.lower() not in title.lower():
        title = f"{service_name}: {title}"

    return title


def generate_canonical_id(finding):
    """Generate a canonical ID for grouping similar findings across tools."""
    check_id = finding.get("check_id", finding.get("type", "unknown"))
    normalized_check = re.sub(
        r"^(prowler_|scoutsuite_|cloudsploit_|polaris_|kube_linter_)",
        "",
        check_id.lower(),
    )
    normalized_check = re.sub(r"[-.\s]+", "_", normalized_check)

    resource_type = finding.get("resource_type", "unknown").lower()
    account_id = finding.get("account_id", "unknown")
    region = finding.get("region", "global").lower()

    canonical_parts = [resource_type, normalized_check, account_id, region]
    canonical_str = "_".join(part for part in canonical_parts if part)

    if len(canonical_str) > 200:
        return hashlib.md5(canonical_str.encode()).hexdigest()

    return canonical_str


def redact_secret(secret: str, visible_chars: int = 4) -> str:
    """Redact a secret value, showing only the first few characters."""
    if not secret or len(secret) <= visible_chars:
        return "[REDACTED]"
    return f"{secret[:visible_chars]}...[REDACTED]"
