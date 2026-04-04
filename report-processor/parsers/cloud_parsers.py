"""Cloud security tool parsers: ScoutSuite, Prowler, CloudSploit."""

import json
import logging
from datetime import datetime

from .utils import enhance_finding, strip_html_tags

logger = logging.getLogger(__name__)


def _parse_scoutsuite_item(item, service, all_services=None):
    """Parse a ScoutSuite item path into resource details with actual configuration lookup."""
    if isinstance(item, str):
        parts = item.split(".")

        region = "global"
        for i, part in enumerate(parts):
            if part == "regions" and i + 1 < len(parts):
                region = parts[i + 1]
                break

        resource_id = item
        resource_name = None
        resource_type = service
        configuration = None

        if all_services and len(parts) >= 3:
            try:
                service_name = parts[0]
                service_data = all_services.get(service_name, {})

                collection_candidates = [
                    "policies", "roles", "users", "groups", "buckets", "vpcs",
                    "security_groups", "instances", "volumes", "trails", "queues",
                    "topics", "keys", "functions",
                    "vaults", "storage_accounts", "servers", "databases", "web_apps",
                    "disks", "images", "snapshots", "caches", "diagnostic_settings",
                    "log_alerts", "log_profiles", "resources_logging",
                    "network_interfaces", "public_ip_addresses", "virtual_networks",
                    "subnets", "application_gateways", "load_balancers",
                    "role_assignments", "role_definitions", "pricings",
                    "auto_provisioning_settings", "security_contacts",
                    "information_protection_policies",
                ]

                if "subscriptions" in parts:
                    sub_idx = parts.index("subscriptions")
                    if sub_idx + 1 < len(parts):
                        sub_id = parts[sub_idx + 1]
                        subscriptions_data = service_data.get("subscriptions", {})
                        sub_data = subscriptions_data.get(sub_id, {})

                        current_data = sub_data
                        remaining_parts = parts[sub_idx + 2:]

                        i = 0
                        while i < len(remaining_parts):
                            part = remaining_parts[i]

                            if part in collection_candidates and isinstance(current_data, dict):
                                collection = current_data.get(part, {})

                                if i + 1 < len(remaining_parts) and isinstance(collection, dict):
                                    resource_key = remaining_parts[i + 1]
                                    next_data = collection.get(resource_key)

                                    if next_data and isinstance(next_data, dict):
                                        configuration = next_data
                                        resource_name = next_data.get(
                                            "name", next_data.get("Name", resource_key)
                                        )
                                        resource_id = next_data.get(
                                            "id", next_data.get("arn", resource_key)
                                        )
                                        if next_data.get("location"):
                                            region = next_data["location"]

                                        current_data = next_data
                                        i += 2
                                        continue

                            i += 1
                else:
                    for i, part in enumerate(parts[1:], 1):
                        if part in collection_candidates and i + 1 < len(parts):
                            collection = service_data.get(part, {})
                            resource_key = parts[i + 1]
                            if part == "regions" and i + 2 < len(parts):
                                region_data = collection.get(parts[i + 1], {})
                                if i + 3 < len(parts) and parts[i + 2] in collection_candidates:
                                    collection = region_data.get(parts[i + 2], {})
                                    resource_key = parts[i + 3] if i + 3 < len(parts) else None

                            if resource_key and isinstance(collection, dict):
                                resource_data = collection.get(resource_key)
                                if resource_data and isinstance(resource_data, dict):
                                    configuration = resource_data
                                    resource_name = resource_data.get(
                                        "name", resource_data.get("Name", resource_key)
                                    )
                                    resource_id = resource_data.get(
                                        "id", resource_data.get("arn", resource_key)
                                    )
                                    break
            except Exception as e:
                logger.debug(f"Could not extract resource details from ScoutSuite path {item}: {e}")

        for i, part in enumerate(parts):
            if part.startswith("vpc-"):
                resource_id = part
                resource_type = "vpc"
            elif part.startswith("sg-"):
                resource_id = part
                resource_type = "security_group"
            elif part.startswith("vol-"):
                resource_id = part
                resource_type = "volume"
            elif part.startswith("acl-"):
                resource_id = part
                resource_type = "network_acl"
            elif part.startswith("i-"):
                resource_id = part
                resource_type = "instance"
            elif part.startswith("arn:"):
                resource_id = part
            elif part.startswith("ANPA") or part.startswith("AROA") or part.startswith("AIDA"):
                resource_id = part
                resource_type = "iam"
            elif part.startswith("scoutid-"):
                resource_id = part
            elif part.startswith("/subscriptions/"):
                resource_id = part
            elif i > 0 and parts[i - 1] in [
                "buckets", "queues", "topics", "roles", "users", "policies",
                "vaults", "storage_accounts", "servers", "web_apps",
                "security_groups", "virtual_networks", "network_interfaces",
            ]:
                if resource_name is None:
                    resource_name = part
                    resource_id = part

        result = {
            "id": resource_id,
            "name": resource_name or resource_id,
            "region": region,
            "type": resource_type,
            "path": item,
        }
        if configuration:
            result["configuration"] = configuration
        return result
    elif isinstance(item, dict):
        return {
            "id": item.get("id", item.get("name", str(item))),
            "name": item.get("name", item.get("id", "")),
            "region": item.get("region", "global"),
            "type": item.get("type", service),
            "configuration": item,
        }
    else:
        return {
            "id": str(item),
            "name": str(item),
            "region": "global",
            "type": service,
        }


def process_scoutsuite_report(report_path, discovered_account_id=None):
    """Process ScoutSuite report (JavaScript or JSON format).

    Creates ONE finding per finding_id with all affected resources stored in affected_resources.

    Args:
        report_path: Path to the ScoutSuite report file.
        discovered_account_id: Previously discovered account ID for cross-reference.

    Returns:
        Tuple of (metadata dict, findings list, discovered_account_id or None).
        The third element allows callers to capture newly discovered account IDs.
    """
    logger.info(f"Processing ScoutSuite report: {report_path}")

    findings = []
    new_account_id = None
    try:
        with open(report_path, encoding="utf-8") as f:
            content = f.read()

        js_prefix_patterns = ["scoutsuite_results =\n", "scoutsuite_results = "]
        json_content = content.strip()

        for prefix in js_prefix_patterns:
            if json_content.startswith(prefix):
                json_content = json_content[len(prefix):]
                break

        if json_content.rstrip().endswith(";"):
            json_content = json_content.rstrip()[:-1]

        data = json.loads(json_content)

        account_id = data.get("aws_account_id", data.get("account_id", "unknown"))
        if account_id and account_id != "unknown":
            new_account_id = account_id

        raw_provider = data.get("provider_name", data.get("provider", "aws"))
        provider_map = {
            "amazon web services": "aws",
            "aws": "aws",
            "azure": "azure",
            "microsoft azure": "azure",
            "google cloud platform": "gcp",
            "gcp": "gcp",
        }
        normalized_provider = provider_map.get(raw_provider.lower(), raw_provider.lower())

        metadata = {
            "tool": "scoutsuite",
            "cloud_provider": normalized_provider,
            "scan_date": datetime.now().isoformat(),
            "account_id": account_id,
        }

        severity_map = {
            "danger": "high",
            "warning": "medium",
            "info": "low",
        }

        all_services = data.get("services", {})

        for service, service_data in all_services.items():
            if not isinstance(service_data, dict):
                continue

            for finding_id, finding_data in service_data.get("findings", {}).items():
                if not isinstance(finding_data, dict):
                    continue

                flagged_count = finding_data.get("flagged_items", 0)
                if flagged_count == 0:
                    continue

                raw_severity = finding_data.get("level", "warning")
                severity = severity_map.get(raw_severity.lower(), "medium")

                items = finding_data.get("items", [])

                finding_description = strip_html_tags(finding_data.get("description", ""))
                finding_rationale = strip_html_tags(finding_data.get("rationale", ""))
                finding_remediation = strip_html_tags(finding_data.get("remediation", ""))

                title_parts = finding_id.replace("-", " ").replace("_", " ").split()
                check_title = " ".join(word.capitalize() for word in title_parts)

                affected_resources = []
                regions_seen = set()
                resource_configs = []

                for item in items:
                    resource_info = _parse_scoutsuite_item(item, service, all_services)
                    affected_resources.append(resource_info)
                    if resource_info.get("region"):
                        regions_seen.add(resource_info["region"])
                    if resource_info.get("configuration"):
                        resource_configs.append(
                            {
                                "id": resource_info.get("id"),
                                "name": resource_info.get("name"),
                                "config": resource_info.get("configuration"),
                            }
                        )

                if len(regions_seen) == 1:
                    primary_region = list(regions_seen)[0]
                elif len(regions_seen) > 1:
                    primary_region = "multiple"
                else:
                    primary_region = "global"

                if len(affected_resources) == 1:
                    resource_name = affected_resources[0].get(
                        "name", affected_resources[0].get("id", check_title)
                    )
                elif len(affected_resources) > 1:
                    resource_name = f"{len(affected_resources)} {service} resources"
                else:
                    resource_name = check_title

                evidence_parts = []
                if resource_configs:
                    evidence_parts.append(
                        f"Found {len(resource_configs)} affected resource(s)"
                    )
                    evidence_parts.append("\nResource Configuration(s):")
                    for rc in resource_configs[:5]:
                        config_json = json.dumps(rc.get("config", {}), indent=2)
                        if len(config_json) > 1500:
                            config_json = config_json[:1500] + "\n  ... (truncated)"
                        evidence_parts.append(
                            f"\n{rc.get('name', rc.get('id', 'Unknown'))}:"
                        )
                        evidence_parts.append(config_json)
                    if len(resource_configs) > 5:
                        evidence_parts.append(
                            f"\n... and {len(resource_configs) - 5} more resource(s)"
                        )

                poc_evidence_text = (
                    "\n".join(evidence_parts) if evidence_parts else ""
                )

                finding = {
                    "service": service,
                    "type": finding_id,
                    "check_id": f"scoutsuite_{finding_id}",
                    "check_title": check_title,
                    "severity": severity,
                    "status": "fail",
                    "resource_id": finding_id,
                    "resource_type": service,
                    "resource_name": resource_name,
                    "region": primary_region,
                    "account_id": account_id,
                    "description": finding_rationale if finding_rationale else check_title,
                    "remediation": finding_remediation,
                    "compliance": finding_data.get("compliance", []),
                    "checked_items": finding_data.get("checked_items", 0),
                    "flagged_items": flagged_count,
                    "affected_resources": affected_resources,
                    "affected_count": len(affected_resources),
                    "poc_verification": "",
                    "poc_evidence": poc_evidence_text,
                }
                finding = enhance_finding(finding, service, finding_id, normalized_provider)
                findings.append(finding)

        logger.info(f"Extracted {len(findings)} findings from ScoutSuite")
        return metadata, findings, new_account_id

    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error in ScoutSuite report: {e}")
        return None, [], None
    except Exception as e:
        logger.error(f"Error processing ScoutSuite report: {e}")
        import traceback
        traceback.print_exc()
        return None, [], None


def _parse_prowler_ocsf(finding_data):
    """Parse Prowler OCSF format finding.

    Returns:
        Tuple of (finding_dict, account_id_or_None).
    """
    try:
        metadata = finding_data.get("metadata", {})
        check_id = metadata.get("event_code", "")
        unmapped = finding_data.get("unmapped", {})
        remediation_data = unmapped.get("remediation", {})
        compliance_data = unmapped.get("compliance", {})

        cloud_data = finding_data.get("cloud", {})
        account_data = cloud_data.get("account", {})
        account_id = account_data.get("uid", "")
        new_account_id = account_id if account_id and account_id != "" else None

        finding_cloud_provider = cloud_data.get("provider", "aws").lower()

        severity_map = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
        severity = severity_map.get(finding_data.get("severity_id", 3), "medium")

        resources = finding_data.get("resources", [{}])
        resource = resources[0] if resources else {}

        remediation_commands = []
        cli_cmd = remediation_data.get("cli", "") or remediation_data.get("CLI", "")

        cli_key = f"{finding_cloud_provider}_cli"
        cli_description = f"{finding_cloud_provider.upper()} CLI remediation command"
        if finding_cloud_provider == "azure":
            cli_description = "Azure CLI remediation command"
        elif finding_cloud_provider == "gcp":
            cli_description = "Google Cloud CLI remediation command"
        else:
            cli_description = "AWS CLI remediation command"

        if cli_cmd:
            remediation_commands.append(
                {
                    "type": "cli",
                    "command": cli_cmd,
                    "description": cli_description,
                }
            )

        remediation_code = {}
        iac = remediation_data.get("terraform", "") or remediation_data.get("NativeIaC", "")
        if iac:
            remediation_code["terraform"] = iac
        if cli_cmd:
            remediation_code[cli_key] = cli_cmd

        remediation_resources = []
        related_url = unmapped.get("related_url", "")
        doc_title = "AWS Documentation"
        if finding_cloud_provider == "azure":
            doc_title = "Azure Documentation"
        elif finding_cloud_provider == "gcp":
            doc_title = "Google Cloud Documentation"
        if related_url:
            remediation_resources.append(
                {
                    "title": doc_title,
                    "url": related_url,
                    "type": "documentation",
                }
            )

        finding_info = finding_data.get("finding_info", {})
        proper_title = (
            finding_info.get("title", "")
            or finding_data.get("activity_name", "")
            or check_id.replace("_", " ").title()
        )

        proper_description = (
            finding_info.get("desc", "")
            or finding_data.get("status_detail", "")
            or finding_data.get("message", "")
        )

        resource_data = resource.get("data", {})
        resource_metadata = resource_data.get("metadata", {})

        evidence_obj = {
            "check_id": check_id,
            "message": finding_data.get("message", ""),
            "status_detail": finding_data.get("status_detail", ""),
            "severity": finding_data.get("severity", ""),
            "risk": unmapped.get("risk", ""),
        }

        if resource_metadata:
            evidence_obj["resource_configuration"] = resource_metadata
        elif resource_data:
            evidence_obj["resource_data"] = resource_data

        evidence_parts = []
        status_detail = finding_data.get("status_detail", "")
        message = finding_data.get("message", "")

        if status_detail or message or resource_metadata:
            if message:
                evidence_parts.append(f"Finding: {message}")
            if status_detail and status_detail != message:
                evidence_parts.append(f"Detail: {status_detail}")
            if resource_metadata:
                config_preview = json.dumps(resource_metadata, indent=2)
                if len(config_preview) > 1500:
                    config_preview = config_preview[:1500] + "\n  ... (truncated)"
                evidence_parts.append(f"\nResource Configuration:\n{config_preview}")

        poc_evidence_text = "\n".join(evidence_parts) if evidence_parts else json.dumps(evidence_obj, indent=2)

        finding = {
            "check_id": check_id,
            "check_title": proper_title,
            "severity": severity,
            "status": "open" if finding_data.get("status_code", "FAIL") != "PASS" else "closed",
            "region": resource.get("region", cloud_data.get("region", "global")),
            "resource_id": resource.get("uid", ""),
            "resource_type": resource.get("type", ""),
            "resource_name": resource.get("name", resource.get("uid", "")),
            "account_id": account_id,
            "description": proper_description,
            "remediation": remediation_data.get(
                "text", remediation_data.get("recommendation", "")
            ),
            "compliance": compliance_data,
            "poc_evidence": poc_evidence_text,
            "poc_verification": "",
            "remediation_commands": remediation_commands,
            "remediation_code": remediation_code,
            "remediation_resources": remediation_resources,
        }
        return finding, new_account_id
    except Exception as e:
        logger.error(f"Error parsing OCSF finding: {e}")
        return None, None


def _parse_prowler_legacy(finding_data, cloud_provider="aws"):
    """Parse Prowler legacy format finding.

    Returns:
        Tuple of (finding_dict, account_id_or_None).
    """
    try:
        account_id = finding_data.get("AccountId", finding_data.get("account_id", ""))
        new_account_id = account_id if account_id and account_id != "" else None

        cli_key = f"{cloud_provider}_cli"

        remediation_obj = finding_data.get("Remediation", {})
        remediation_text = remediation_obj.get("Recommendation", {})
        if isinstance(remediation_text, dict):
            remediation_text = remediation_text.get("Text", "")

        code_obj = remediation_obj.get("Code", {})
        cli_command = code_obj.get("CLI", "")
        native_iac = code_obj.get("NativeIaC", "")

        remediation_commands = []
        cli_description = "AWS CLI command to remediate"
        if cloud_provider == "azure":
            cli_description = "Azure CLI command to remediate"
        elif cloud_provider == "gcp":
            cli_description = "Google Cloud CLI command to remediate"
        if cli_command:
            remediation_commands.append(
                {
                    "type": "cli",
                    "command": cli_command,
                    "description": cli_description,
                }
            )

        remediation_code = {}
        if native_iac:
            remediation_code["terraform"] = native_iac
        if cli_command:
            remediation_code[cli_key] = cli_command

        remediation_resources = []
        remediation_url = remediation_obj.get("Recommendation", {})
        doc_title = "AWS Documentation"
        if cloud_provider == "azure":
            doc_title = "Azure Documentation"
        elif cloud_provider == "gcp":
            doc_title = "Google Cloud Documentation"
        if isinstance(remediation_url, dict) and remediation_url.get("Url"):
            remediation_resources.append(
                {
                    "title": doc_title,
                    "url": remediation_url.get("Url"),
                    "type": "documentation",
                }
            )

        finding = {
            "check_id": finding_data.get("CheckID", ""),
            "check_title": finding_data.get("CheckTitle", ""),
            "severity": finding_data.get("Severity", "unknown"),
            "status": finding_data.get("Status", ""),
            "region": finding_data.get("Region", "global"),
            "resource_id": finding_data.get("ResourceId", ""),
            "resource_type": finding_data.get("ResourceType", ""),
            "resource_name": finding_data.get(
                "ResourceName", finding_data.get("ResourceId", "")
            ),
            "account_id": account_id,
            "description": finding_data.get("StatusExtended", ""),
            "remediation": remediation_text
            if isinstance(remediation_text, str)
            else str(remediation_text),
            "compliance": finding_data.get("Compliance", []),
            "poc_evidence": f"Check: {finding_data.get('CheckID', '')}\n"
                f"Status: {finding_data.get('StatusExtended', '')}\n"
                f"Risk: {finding_data.get('Risk', '')}\n"
                f"Resource Details: {finding_data.get('ResourceDetails', '')}",
            "poc_verification": "",
            "remediation_commands": remediation_commands,
            "remediation_code": remediation_code,
            "remediation_resources": remediation_resources,
        }
        return finding, new_account_id
    except Exception as e:
        logger.error(f"Error parsing legacy finding: {e}")
        return None, None


def process_prowler_report(report_path, discovered_account_id=None):
    """Process Prowler JSON report (supports both OCSF and legacy formats).

    Returns:
        Tuple of (metadata, findings, discovered_account_id).
    """
    logger.info(f"Processing Prowler report: {report_path}")

    findings = []
    detected_provider = None
    new_account_id = discovered_account_id

    report_path_str = str(report_path)
    path_detected_provider = "aws"
    if "prowler-azure" in report_path_str or "/azure/" in report_path_str:
        path_detected_provider = "azure"
    elif "prowler-gcp" in report_path_str or "/gcp/" in report_path_str:
        path_detected_provider = "gcp"

    try:
        with open(report_path) as f:
            content = f.read()

        try:
            data = json.loads(content)
            if isinstance(data, list):
                for finding_data in data:
                    if detected_provider is None:
                        cloud_data = finding_data.get("cloud", {})
                        detected_provider = cloud_data.get("provider", "").lower() or path_detected_provider
                    finding, acct_id = _parse_prowler_ocsf(finding_data)
                    if acct_id:
                        new_account_id = acct_id
                    if finding:
                        service = finding.get("resource_type", "aws")
                        check_id = finding.get("check_id", "")
                        provider = detected_provider or path_detected_provider
                        finding = enhance_finding(finding, service, check_id, provider)
                        findings.append(finding)
            else:
                finding, acct_id = _parse_prowler_legacy(data, path_detected_provider)
                if acct_id:
                    new_account_id = acct_id
                if finding:
                    service = finding.get("resource_type", "aws")
                    check_id = finding.get("check_id", "")
                    finding = enhance_finding(finding, service, check_id, path_detected_provider)
                    findings.append(finding)
        except json.JSONDecodeError:
            for line in content.split("\n"):
                if line.strip():
                    try:
                        finding_data = json.loads(line)
                        finding, acct_id = _parse_prowler_legacy(finding_data, path_detected_provider)
                        if acct_id:
                            new_account_id = acct_id
                        if finding:
                            service = finding.get("resource_type", "aws")
                            check_id = finding.get("check_id", "")
                            finding = enhance_finding(finding, service, check_id, path_detected_provider)
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        if not detected_provider:
            detected_provider = path_detected_provider

        metadata = {
            "tool": "prowler",
            "cloud_provider": detected_provider,
            "scan_date": datetime.now().isoformat(),
        }

        logger.info(f"Extracted {len(findings)} findings from Prowler")
        return metadata, findings, new_account_id

    except Exception as e:
        logger.error(f"Error processing Prowler report: {e}")
        return None, [], None


def process_cloudsploit_report(report_path, discovered_account_id=None):
    """Process CloudSploit JSON report.

    Returns:
        Tuple of (metadata, findings).
    """
    logger.info(f"Processing CloudSploit report: {report_path}")

    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)

        account_id = discovered_account_id or "unknown"

        metadata = {
            "tool": "cloudsploit",
            "cloud_provider": "aws",
            "scan_date": datetime.now().isoformat(),
            "account_id": account_id,
        }

        if not isinstance(data, list):
            logger.warning(f"CloudSploit report is not a JSON array: {report_path}")
            return None, []

        status_severity_map = {"FAIL": "critical", "WARN": "medium"}

        for item in data:
            status = item.get("status", "").upper()

            if status not in status_severity_map:
                continue

            severity = status_severity_map[status]

            compliance_text = item.get("compliance", "")
            compliance_frameworks = []
            if compliance_text:
                if ":" in compliance_text:
                    framework_name = compliance_text.split(":")[0].strip()
                    compliance_frameworks.append(
                        {
                            "framework": framework_name,
                            "requirement": compliance_text,
                        }
                    )
                else:
                    compliance_frameworks.append(
                        {"framework": "General", "requirement": compliance_text}
                    )

            evidence_message = item.get("message", "")
            resource_id = item.get("resource", "N/A")
            category = item.get("category", "")

            verification_parts = []
            if evidence_message:
                verification_parts.append("Scan Evidence:")
                verification_parts.append(f"  {evidence_message}")
            if resource_id and resource_id != "N/A":
                verification_parts.append(f"\nAffected Resource: {resource_id}")

            poc_verification_text = "\n".join(verification_parts) if verification_parts else ""

            finding = {
                "check_id": item.get("plugin", ""),
                "check_title": item.get("title", ""),
                "severity": severity,
                "status": "open",
                "region": item.get("region", "global"),
                "resource_id": resource_id,
                "resource_type": category,
                "resource_name": resource_id,
                "account_id": account_id,
                "description": item.get("description", ""),
                "remediation": "",
                "compliance": compliance_frameworks,
                "poc_evidence": json.dumps(
                    {
                        "plugin": item.get("plugin", ""),
                        "category": category,
                        "status": status,
                        "message": evidence_message,
                        "compliance": compliance_text,
                        "resource": resource_id,
                    },
                    indent=2,
                ),
                "poc_verification": poc_verification_text,
                "remediation_commands": [],
                "remediation_code": {},
                "remediation_resources": [],
            }
            service = item.get("category", "aws")
            check_id = item.get("plugin", "")
            finding = enhance_finding(finding, service, check_id, "aws")
            findings.append(finding)

        logger.info(
            f"Extracted {len(findings)} findings from CloudSploit (filtered OK/UNKNOWN)"
        )
        return metadata, findings

    except Exception as e:
        logger.error(f"Error processing CloudSploit report: {e}")
        return None, []
