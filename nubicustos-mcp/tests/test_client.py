"""Contract tests for NubicustosClient — verify every method hits the correct
endpoint with the expected parameters and body."""

import httpx
import respx

from nubicustos_mcp.client import NubicustosClient

BASE = "http://test-api:8000"


# ---------------------------------------------------------------------------
# Scan Management
# ---------------------------------------------------------------------------


async def test_list_scans_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/scans").mock(return_value=httpx.Response(200, json={"scans": []}))

    result = await client.list_scans()

    assert result == {"scans": []}
    call = mock_api.calls.last
    assert call.request.url.params["page"] == "1"
    assert call.request.url.params["page_size"] == "20"
    assert "status" not in call.request.url.params
    assert "tool" not in call.request.url.params


async def test_list_scans_with_filters(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/scans").mock(return_value=httpx.Response(200, json={"scans": []}))

    await client.list_scans(status="running", tool="prowler", page=2, page_size=10)

    call = mock_api.calls.last
    assert call.request.url.params["status"] == "running"
    assert call.request.url.params["tool"] == "prowler"
    assert call.request.url.params["page"] == "2"
    assert call.request.url.params["page_size"] == "10"


async def test_trigger_scan_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/scans").mock(return_value=httpx.Response(201, json={"scan_id": "abc"}))

    result = await client.trigger_scan()

    assert result == {"scan_id": "abc"}
    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["profile"] == "comprehensive"
    assert body["dry_run"] is False
    assert "target" not in body
    assert "severity_filter" not in body


async def test_trigger_scan_with_all_params(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/scans").mock(return_value=httpx.Response(201, json={"scan_id": "xyz"}))

    await client.trigger_scan(
        profile="quick", target="aws-account-123", severity_filter="critical,high", dry_run=True
    )

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["profile"] == "quick"
    assert body["target"] == "aws-account-123"
    assert body["severity_filter"] == "critical,high"
    assert body["dry_run"] is True


async def test_get_scan_status(client: NubicustosClient, mock_api: respx.Router):
    scan_id = "550e8400-e29b-41d4-a716-446655440000"
    mock_api.get(f"/api/scans/{scan_id}/status").mock(
        return_value=httpx.Response(200, json={"status": "running"})
    )

    result = await client.get_scan_status(scan_id)

    assert result == {"status": "running"}
    assert str(mock_api.calls.last.request.url).endswith(f"/api/scans/{scan_id}/status")


async def test_cancel_scan(client: NubicustosClient, mock_api: respx.Router):
    scan_id = "abc-123"
    mock_api.delete(f"/api/scans/{scan_id}").mock(
        return_value=httpx.Response(200, json={"cancelled": True})
    )

    result = await client.cancel_scan(scan_id)

    assert result == {"cancelled": True}
    assert mock_api.calls.last.request.method == "DELETE"


async def test_list_scan_profiles(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/scans/profiles/list").mock(
        return_value=httpx.Response(200, json={"profiles": []})
    )

    result = await client.list_scan_profiles()

    assert result == {"profiles": []}


# ---------------------------------------------------------------------------
# Finding Queries
# ---------------------------------------------------------------------------


async def test_search_findings_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/findings").mock(return_value=httpx.Response(200, json={"findings": []}))

    result = await client.search_findings()

    assert result == {"findings": []}
    params = mock_api.calls.last.request.url.params
    assert params["page"] == "1"
    assert params["page_size"] == "50"
    assert params["sort_by"] == "risk_score"


async def test_search_findings_with_filters(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/findings").mock(return_value=httpx.Response(200, json={"findings": []}))

    await client.search_findings(
        search="s3 bucket",
        severity="critical",
        status="open",
        cloud_provider="aws",
        tool="prowler",
        resource_type="S3",
        sort_by="severity",
        page=3,
        page_size=25,
    )

    params = mock_api.calls.last.request.url.params
    assert params["search"] == "s3 bucket"
    assert params["severity"] == "critical"
    assert params["status"] == "open"
    assert params["cloud_provider"] == "aws"
    assert params["tool"] == "prowler"
    assert params["resource_type"] == "S3"
    assert params["sort_by"] == "severity"
    assert params["page"] == "3"
    assert params["page_size"] == "25"


async def test_get_findings_summary_no_filter(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/findings/summary").mock(
        return_value=httpx.Response(200, json={"total": 42})
    )

    result = await client.get_findings_summary()

    assert result == {"total": 42}
    # No params when no status filter
    assert "status" not in mock_api.calls.last.request.url.params


async def test_get_findings_summary_with_status(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/findings/summary").mock(
        return_value=httpx.Response(200, json={"total": 10})
    )

    await client.get_findings_summary(status="open")

    assert mock_api.calls.last.request.url.params["status"] == "open"


async def test_get_finding_details(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/findings/42").mock(
        return_value=httpx.Response(200, json={"id": 42, "title": "Open S3"})
    )

    result = await client.get_finding_details(42)

    assert result["id"] == 42


async def test_update_finding_status(client: NubicustosClient, mock_api: respx.Router):
    mock_api.patch("/api/findings/7").mock(
        return_value=httpx.Response(200, json={"id": 7, "status": "mitigated"})
    )

    result = await client.update_finding_status(7, status="mitigated")

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body == {"status": "mitigated"}
    assert result["status"] == "mitigated"


async def test_update_finding_status_with_tags(client: NubicustosClient, mock_api: respx.Router):
    mock_api.patch("/api/findings/7").mock(
        return_value=httpx.Response(200, json={"id": 7, "status": "accepted"})
    )

    tags = {"team": "platform", "ticket": "SEC-123"}
    await client.update_finding_status(7, status="accepted", tags=tags)

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["status"] == "accepted"
    assert body["tags"] == tags


# ---------------------------------------------------------------------------
# Attack Paths
# ---------------------------------------------------------------------------


async def test_list_attack_paths_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/attack-paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    result = await client.list_attack_paths()

    assert result == {"paths": []}
    params = mock_api.calls.last.request.url.params
    assert params["page"] == "1"
    assert params["page_size"] == "20"


async def test_list_attack_paths_with_filters(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/attack-paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    await client.list_attack_paths(
        min_risk_score=80, exploitability="confirmed",
        entry_point_type="public", target_type="database",
    )

    params = mock_api.calls.last.request.url.params
    assert params["min_risk_score"] == "80"
    assert params["exploitability"] == "confirmed"
    assert params["entry_point_type"] == "public"
    assert params["target_type"] == "database"


async def test_get_attack_path_details_default_format(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/attack-paths/5").mock(
        return_value=httpx.Response(200, json={"id": 5})
    )

    result = await client.get_attack_path_details(5)

    assert result["id"] == 5
    # Default format is json, which means no params sent
    assert "format" not in mock_api.calls.last.request.url.params


async def test_get_attack_path_details_markdown(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/attack-paths/5").mock(
        return_value=httpx.Response(200, json={"id": 5})
    )

    await client.get_attack_path_details(5, format="markdown")

    assert mock_api.calls.last.request.url.params["format"] == "markdown"


async def test_analyze_attack_paths_no_scan(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/attack-paths/analyze").mock(
        return_value=httpx.Response(200, json={"paths_found": 3})
    )

    result = await client.analyze_attack_paths()

    assert result["paths_found"] == 3
    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body == {}


async def test_analyze_attack_paths_with_scan_id(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/attack-paths/analyze").mock(
        return_value=httpx.Response(200, json={"paths_found": 1})
    )

    await client.analyze_attack_paths(scan_id="scan-uuid")

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body == {"scan_id": "scan-uuid"}


# ---------------------------------------------------------------------------
# Security Analysis
# ---------------------------------------------------------------------------


async def test_list_privesc_paths_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/privesc-paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    result = await client.list_privesc_paths()

    assert result == {"paths": []}
    params = mock_api.calls.last.request.url.params
    assert params["page"] == "1"
    assert params["page_size"] == "20"


async def test_list_privesc_paths_with_filters(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/privesc-paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    await client.list_privesc_paths(min_risk_score=70, status="open")

    params = mock_api.calls.last.request.url.params
    assert params["min_risk_score"] == "70"
    assert params["status"] == "open"


async def test_get_public_exposures_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/public-exposures").mock(
        return_value=httpx.Response(200, json={"exposures": []})
    )

    result = await client.get_public_exposures()

    assert result == {"exposures": []}


async def test_get_public_exposures_with_filters(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/public-exposures").mock(
        return_value=httpx.Response(200, json={"exposures": []})
    )

    await client.get_public_exposures(
        exposure_type="PublicS3Bucket", risk_level="critical",
        is_internet_exposed=True,
    )

    params = mock_api.calls.last.request.url.params
    assert params["exposure_type"] == "PublicS3Bucket"
    assert params["risk_level"] == "critical"
    assert params["is_internet_exposed"] == "true"


async def test_get_exposed_credentials_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/exposed-credentials").mock(
        return_value=httpx.Response(200, json={"credentials": []})
    )

    result = await client.get_exposed_credentials()

    assert result == {"credentials": []}


async def test_get_exposed_credentials_with_filters(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/exposed-credentials").mock(
        return_value=httpx.Response(200, json={"credentials": []})
    )

    await client.get_exposed_credentials(
        credential_type="AWS_ACCESS_KEY",
        source_type="Environment variables",
        remediation_status="pending",
    )

    params = mock_api.calls.last.request.url.params
    assert params["credential_type"] == "AWS_ACCESS_KEY"
    assert params["source_type"] == "Environment variables"
    assert params["remediation_status"] == "pending"


# ---------------------------------------------------------------------------
# Cloud-Specific
# ---------------------------------------------------------------------------


async def test_get_imds_checks_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/imds-checks").mock(
        return_value=httpx.Response(200, json={"checks": []})
    )

    result = await client.get_imds_checks()

    assert result == {"checks": []}


async def test_get_imds_checks_with_filter(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/imds-checks").mock(
        return_value=httpx.Response(200, json={"checks": []})
    )

    await client.get_imds_checks(risk_level="high")

    assert mock_api.calls.last.request.url.params["risk_level"] == "high"


async def test_get_lambda_analysis_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/lambda-analysis").mock(
        return_value=httpx.Response(200, json={"functions": []})
    )

    result = await client.get_lambda_analysis()

    assert result == {"functions": []}


async def test_get_lambda_analysis_with_filter(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/lambda-analysis").mock(
        return_value=httpx.Response(200, json={"functions": []})
    )

    await client.get_lambda_analysis(risk_level="critical", page=2, page_size=5)

    params = mock_api.calls.last.request.url.params
    assert params["risk_level"] == "critical"
    assert params["page"] == "2"
    assert params["page_size"] == "5"


async def test_run_cloudfox_module_only(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/cloudfox/run").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    result = await client.run_cloudfox("instances")

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["modules"] == ["instances"]
    assert "profile" not in body
    assert result == {"results": []}


async def test_run_cloudfox_with_target(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/cloudfox/run").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    await client.run_cloudfox("org-principals", target_account="123456789012")

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["modules"] == ["org-principals"]
    assert body["profile"] == "123456789012"


async def test_run_enumerate_iam(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/enumerate-iam/run").mock(
        return_value=httpx.Response(200, json={"permissions": []})
    )

    result = await client.run_enumerate_iam(
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        principal_arn="arn:aws:iam::123456789012:role/admin",
    )

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["access_key"] == "AKIAIOSFODNN7EXAMPLE"
    assert body["secret_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert body["region"] == "us-east-1"
    assert body["principal_arn"] == "arn:aws:iam::123456789012:role/admin"
    assert "session_token" not in body
    assert result == {"permissions": []}


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


async def test_export_findings_defaults(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/exports/generate").mock(
        return_value=httpx.Response(200, json={"export_id": "e1"})
    )

    result = await client.export_findings()

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["format"] == "json"
    assert body["status_filter"] == ["open"]
    assert "severity_filter" not in body
    assert "cloud_provider" not in body
    assert result["export_id"] == "e1"


async def test_export_findings_with_all_params(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/exports/generate").mock(
        return_value=httpx.Response(200, json={"export_id": "e2"})
    )

    await client.export_findings(
        format="csv", severity="critical,high", status="open,mitigated", cloud_provider="aws"
    )

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["format"] == "csv"
    assert body["severity_filter"] == ["critical", "high"]
    assert body["status_filter"] == ["open", "mitigated"]
    assert body["cloud_provider"] == "aws"


async def test_get_export_summary(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/exports/summary").mock(
        return_value=httpx.Response(200, json={"total_findings": 99})
    )

    result = await client.get_export_summary()

    assert result == {"total_findings": 99}


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------


async def test_check_health_basic(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/health").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    result = await client.check_health()

    assert result == {"status": "ok"}
    assert str(mock_api.calls.last.request.url).endswith("/api/health")


async def test_check_health_detailed(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/health/detailed").mock(
        return_value=httpx.Response(200, json={"status": "ok", "db": "ok"})
    )

    result = await client.check_health(detailed=True)

    assert result["db"] == "ok"
    assert str(mock_api.calls.last.request.url).endswith("/api/health/detailed")


async def test_get_sync_status(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/sync/status").mock(
        return_value=httpx.Response(200, json={"synced": True})
    )

    result = await client.get_sync_status()

    assert result == {"synced": True}


async def test_verify_credentials(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/credentials/verify").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )

    creds = {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "secret"}
    result = await client.verify_credentials("aws", credentials=creds)

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body["provider"] == "aws"
    assert body["aws"] == creds
    assert result == {"valid": True}


async def test_verify_credentials_no_creds(client: NubicustosClient, mock_api: respx.Router):
    mock_api.post("/api/credentials/verify").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )

    result = await client.verify_credentials("aws")

    import json
    body = json.loads(mock_api.calls.last.request.content)
    assert body == {"provider": "aws"}
    assert "aws" not in body or body == {"provider": "aws"}
    assert result == {"valid": True}


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


async def test_api_error_raises(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/scans").mock(
        return_value=httpx.Response(500, json={"detail": "Internal Server Error"})
    )

    import pytest
    from nubicustos_mcp.client import NubicustosAPIError

    with pytest.raises(NubicustosAPIError) as exc_info:
        await client.list_scans()

    assert exc_info.value.status_code == 500
    assert "Internal Server Error" in exc_info.value.message


async def test_api_key_header_sent(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/health").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    await client.check_health()

    assert mock_api.calls.last.request.headers["X-API-Key"] == "test-key"


async def test_content_type_header(client: NubicustosClient, mock_api: respx.Router):
    mock_api.get("/api/health").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    await client.check_health()

    assert mock_api.calls.last.request.headers["Content-Type"] == "application/json"
