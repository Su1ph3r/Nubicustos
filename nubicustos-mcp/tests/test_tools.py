"""Tool-layer tests — verify each MCP tool function delegates to the correct
client method with the right arguments."""

from unittest.mock import AsyncMock, patch

from mcp.server.fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mcp_and_register(register_fn) -> dict[str, callable]:
    """Create a throwaway FastMCP, register tools, and return the tool map."""
    mcp = FastMCP("test")
    register_fn(mcp)
    # FastMCP stores tools in _tool_manager._tools (name -> Tool)
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


# ---------------------------------------------------------------------------
# Scan tools
# ---------------------------------------------------------------------------


class TestScanTools:

    @patch("nubicustos_mcp.tools.scans.client")
    async def test_list_scans(self, mock_client):
        from nubicustos_mcp.tools.scans import register_scan_tools

        mock_client.list_scans = AsyncMock(return_value={"scans": []})
        tools = _make_mcp_and_register(register_scan_tools)

        result = await tools["list_scans"](status="running", tool="prowler", page=2, page_size=10)

        mock_client.list_scans.assert_awaited_once_with(
            status="running", tool="prowler", page=2, page_size=10
        )
        assert result == {"scans": []}

    @patch("nubicustos_mcp.tools.scans.client")
    async def test_trigger_scan(self, mock_client):
        from nubicustos_mcp.tools.scans import register_scan_tools

        mock_client.trigger_scan = AsyncMock(return_value={"scan_id": "abc"})
        tools = _make_mcp_and_register(register_scan_tools)

        result = await tools["trigger_scan"](
            profile="quick", target="acct", severity_filter="high", dry_run=True
        )

        mock_client.trigger_scan.assert_awaited_once_with(
            profile="quick", target="acct", severity_filter="high", dry_run=True
        )
        assert result["scan_id"] == "abc"

    @patch("nubicustos_mcp.tools.scans.client")
    async def test_get_scan_status(self, mock_client):
        from nubicustos_mcp.tools.scans import register_scan_tools

        mock_client.get_scan_status = AsyncMock(return_value={"status": "completed"})
        tools = _make_mcp_and_register(register_scan_tools)

        result = await tools["get_scan_status"](scan_id="uuid-1")

        mock_client.get_scan_status.assert_awaited_once_with("uuid-1")

    @patch("nubicustos_mcp.tools.scans.client")
    async def test_cancel_scan(self, mock_client):
        from nubicustos_mcp.tools.scans import register_scan_tools

        mock_client.cancel_scan = AsyncMock(return_value={"cancelled": True})
        tools = _make_mcp_and_register(register_scan_tools)

        await tools["cancel_scan"](scan_id="uuid-2")

        mock_client.cancel_scan.assert_awaited_once_with("uuid-2")

    @patch("nubicustos_mcp.tools.scans.client")
    async def test_list_scan_profiles(self, mock_client):
        from nubicustos_mcp.tools.scans import register_scan_tools

        mock_client.list_scan_profiles = AsyncMock(return_value={"profiles": []})
        tools = _make_mcp_and_register(register_scan_tools)

        await tools["list_scan_profiles"]()

        mock_client.list_scan_profiles.assert_awaited_once()


# ---------------------------------------------------------------------------
# Finding tools
# ---------------------------------------------------------------------------


class TestFindingTools:

    @patch("nubicustos_mcp.tools.findings.client")
    async def test_search_findings(self, mock_client):
        from nubicustos_mcp.tools.findings import register_finding_tools

        mock_client.search_findings = AsyncMock(return_value={"findings": []})
        tools = _make_mcp_and_register(register_finding_tools)

        await tools["search_findings"](
            search="s3", severity="critical", status="open",
            cloud_provider="aws", tool="prowler", resource_type="S3",
            sort_by="severity", page=1, page_size=50,
        )

        mock_client.search_findings.assert_awaited_once_with(
            search="s3", severity="critical", status="open",
            cloud_provider="aws", tool="prowler", resource_type="S3",
            sort_by="severity", page=1, page_size=50,
        )

    @patch("nubicustos_mcp.tools.findings.client")
    async def test_get_findings_summary(self, mock_client):
        from nubicustos_mcp.tools.findings import register_finding_tools

        mock_client.get_findings_summary = AsyncMock(return_value={"total": 5})
        tools = _make_mcp_and_register(register_finding_tools)

        await tools["get_findings_summary"](status="open")

        mock_client.get_findings_summary.assert_awaited_once_with(status="open")

    @patch("nubicustos_mcp.tools.findings.client")
    async def test_get_finding_details(self, mock_client):
        from nubicustos_mcp.tools.findings import register_finding_tools

        mock_client.get_finding_details = AsyncMock(return_value={"id": 42})
        tools = _make_mcp_and_register(register_finding_tools)

        await tools["get_finding_details"](finding_id=42)

        mock_client.get_finding_details.assert_awaited_once_with(42)

    @patch("nubicustos_mcp.tools.findings.client")
    async def test_update_finding_status(self, mock_client):
        from nubicustos_mcp.tools.findings import register_finding_tools

        mock_client.update_finding_status = AsyncMock(return_value={"id": 7})
        tools = _make_mcp_and_register(register_finding_tools)

        tags = {"team": "sec"}
        await tools["update_finding_status"](finding_id=7, status="mitigated", tags=tags)

        mock_client.update_finding_status.assert_awaited_once_with(
            finding_id=7, status="mitigated", tags=tags
        )


# ---------------------------------------------------------------------------
# Attack path tools
# ---------------------------------------------------------------------------


class TestAttackPathTools:

    @patch("nubicustos_mcp.tools.attack_paths.client")
    async def test_list_attack_paths(self, mock_client):
        from nubicustos_mcp.tools.attack_paths import register_attack_path_tools

        mock_client.list_attack_paths = AsyncMock(return_value={"paths": []})
        tools = _make_mcp_and_register(register_attack_path_tools)

        await tools["list_attack_paths"](
            min_risk_score=80, exploitability="confirmed",
            entry_point_type="public", target_type="database",
            page=1, page_size=20,
        )

        mock_client.list_attack_paths.assert_awaited_once_with(
            min_risk_score=80, exploitability="confirmed",
            entry_point_type="public", target_type="database",
            page=1, page_size=20,
        )

    @patch("nubicustos_mcp.tools.attack_paths.client")
    async def test_get_attack_path_details(self, mock_client):
        from nubicustos_mcp.tools.attack_paths import register_attack_path_tools

        mock_client.get_attack_path_details = AsyncMock(return_value={"id": 5})
        tools = _make_mcp_and_register(register_attack_path_tools)

        await tools["get_attack_path_details"](path_id=5, format="markdown")

        mock_client.get_attack_path_details.assert_awaited_once_with(
            path_id=5, format="markdown"
        )

    @patch("nubicustos_mcp.tools.attack_paths.client")
    async def test_analyze_attack_paths(self, mock_client):
        from nubicustos_mcp.tools.attack_paths import register_attack_path_tools

        mock_client.analyze_attack_paths = AsyncMock(return_value={"paths_found": 2})
        tools = _make_mcp_and_register(register_attack_path_tools)

        await tools["analyze_attack_paths"](scan_id="scan-1")

        mock_client.analyze_attack_paths.assert_awaited_once_with(scan_id="scan-1")


# ---------------------------------------------------------------------------
# Security tools
# ---------------------------------------------------------------------------


class TestSecurityTools:

    @patch("nubicustos_mcp.tools.security.client")
    async def test_list_privesc_paths(self, mock_client):
        from nubicustos_mcp.tools.security import register_security_tools

        mock_client.list_privesc_paths = AsyncMock(return_value={"paths": []})
        tools = _make_mcp_and_register(register_security_tools)

        await tools["list_privesc_paths"](
            min_risk_score=70, status="open", page=1, page_size=20
        )

        mock_client.list_privesc_paths.assert_awaited_once_with(
            min_risk_score=70, status="open", page=1, page_size=20
        )

    @patch("nubicustos_mcp.tools.security.client")
    async def test_get_public_exposures(self, mock_client):
        from nubicustos_mcp.tools.security import register_security_tools

        mock_client.get_public_exposures = AsyncMock(return_value={"exposures": []})
        tools = _make_mcp_and_register(register_security_tools)

        await tools["get_public_exposures"](
            exposure_type="PublicS3Bucket", risk_level="critical",
            is_internet_exposed=True, page=1, page_size=20,
        )

        mock_client.get_public_exposures.assert_awaited_once_with(
            exposure_type="PublicS3Bucket", risk_level="critical",
            is_internet_exposed=True, page=1, page_size=20,
        )

    @patch("nubicustos_mcp.tools.security.client")
    async def test_get_exposed_credentials(self, mock_client):
        from nubicustos_mcp.tools.security import register_security_tools

        mock_client.get_exposed_credentials = AsyncMock(return_value={"credentials": []})
        tools = _make_mcp_and_register(register_security_tools)

        await tools["get_exposed_credentials"](
            credential_type="AWS_ACCESS_KEY",
            source_type="Environment variables",
            remediation_status="pending",
            page=1, page_size=20,
        )

        mock_client.get_exposed_credentials.assert_awaited_once_with(
            credential_type="AWS_ACCESS_KEY",
            source_type="Environment variables",
            remediation_status="pending",
            page=1, page_size=20,
        )


# ---------------------------------------------------------------------------
# Cloud tools
# ---------------------------------------------------------------------------


class TestCloudTools:

    @patch("nubicustos_mcp.tools.cloud.client")
    async def test_get_imds_checks(self, mock_client):
        from nubicustos_mcp.tools.cloud import register_cloud_tools

        mock_client.get_imds_checks = AsyncMock(return_value={"checks": []})
        tools = _make_mcp_and_register(register_cloud_tools)

        await tools["get_imds_checks"](risk_level="high", page=1, page_size=20)

        mock_client.get_imds_checks.assert_awaited_once_with(
            risk_level="high", page=1, page_size=20
        )

    @patch("nubicustos_mcp.tools.cloud.client")
    async def test_get_lambda_analysis(self, mock_client):
        from nubicustos_mcp.tools.cloud import register_cloud_tools

        mock_client.get_lambda_analysis = AsyncMock(return_value={"functions": []})
        tools = _make_mcp_and_register(register_cloud_tools)

        await tools["get_lambda_analysis"](risk_level="critical", page=2, page_size=5)

        mock_client.get_lambda_analysis.assert_awaited_once_with(
            risk_level="critical", page=2, page_size=5
        )

    @patch("nubicustos_mcp.tools.cloud.client")
    async def test_run_cloudfox(self, mock_client):
        from nubicustos_mcp.tools.cloud import register_cloud_tools

        mock_client.run_cloudfox = AsyncMock(return_value={"results": []})
        tools = _make_mcp_and_register(register_cloud_tools)

        await tools["run_cloudfox"](module_name="instances", target_account="123456789012")

        mock_client.run_cloudfox.assert_awaited_once_with(
            module_name="instances", target_account="123456789012"
        )

    @patch("nubicustos_mcp.tools.cloud.client")
    async def test_run_enumerate_iam(self, mock_client):
        from nubicustos_mcp.tools.cloud import register_cloud_tools

        mock_client.run_enumerate_iam = AsyncMock(return_value={"permissions": []})
        tools = _make_mcp_and_register(register_cloud_tools)

        await tools["run_enumerate_iam"](
            access_key="AKID", secret_key="secret", region="us-east-1"
        )

        mock_client.run_enumerate_iam.assert_awaited_once_with(
            access_key="AKID",
            secret_key="secret",
            session_token=None,
            region="us-east-1",
            principal_arn=None,
        )


# ---------------------------------------------------------------------------
# Export tools
# ---------------------------------------------------------------------------


class TestExportTools:

    @patch("nubicustos_mcp.tools.exports.client")
    async def test_export_findings(self, mock_client):
        from nubicustos_mcp.tools.exports import register_export_tools

        mock_client.export_findings = AsyncMock(return_value={"export_id": "e1"})
        tools = _make_mcp_and_register(register_export_tools)

        await tools["export_findings"](
            format="csv", severity="critical,high", status="open", cloud_provider="aws"
        )

        mock_client.export_findings.assert_awaited_once_with(
            format="csv", severity="critical,high", status="open", cloud_provider="aws"
        )

    @patch("nubicustos_mcp.tools.exports.client")
    async def test_get_export_summary(self, mock_client):
        from nubicustos_mcp.tools.exports import register_export_tools

        mock_client.get_export_summary = AsyncMock(return_value={"total": 99})
        tools = _make_mcp_and_register(register_export_tools)

        await tools["get_export_summary"]()

        mock_client.get_export_summary.assert_awaited_once()


# ---------------------------------------------------------------------------
# System tools
# ---------------------------------------------------------------------------


class TestSystemTools:

    @patch("nubicustos_mcp.tools.system.client")
    async def test_check_health(self, mock_client):
        from nubicustos_mcp.tools.system import register_system_tools

        mock_client.check_health = AsyncMock(return_value={"status": "ok"})
        tools = _make_mcp_and_register(register_system_tools)

        await tools["check_health"](detailed=True)

        mock_client.check_health.assert_awaited_once_with(detailed=True)

    @patch("nubicustos_mcp.tools.system.client")
    async def test_get_sync_status(self, mock_client):
        from nubicustos_mcp.tools.system import register_system_tools

        mock_client.get_sync_status = AsyncMock(return_value={"synced": True})
        tools = _make_mcp_and_register(register_system_tools)

        await tools["get_sync_status"]()

        mock_client.get_sync_status.assert_awaited_once()

    @patch("nubicustos_mcp.tools.system.client")
    async def test_verify_credentials(self, mock_client):
        from nubicustos_mcp.tools.system import register_system_tools

        mock_client.verify_credentials = AsyncMock(return_value={"valid": True})
        tools = _make_mcp_and_register(register_system_tools)

        creds = {"access_key_id": "AKID"}
        await tools["verify_credentials"](provider="aws", credentials=creds)

        mock_client.verify_credentials.assert_awaited_once_with(
            provider="aws", credentials=creds
        )
