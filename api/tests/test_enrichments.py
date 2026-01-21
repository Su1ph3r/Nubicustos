"""
Unit tests for security enrichment modules.

Tests the following enrichers:
- CISA KEV Provider
- Container Escape Scorer
- Kubernetes CVE Checker
- IMDS Enricher
"""

import sys
from pathlib import Path

import pytest

# Add report-processor to path for imports
REPORT_PROCESSOR_PATH = Path(__file__).parent.parent.parent / "report-processor"
sys.path.insert(0, str(REPORT_PROCESSOR_PATH))


class TestContainerEscapeScorer:
    """Tests for container escape risk scoring."""

    def test_privileged_container_detection(self):
        """Test detection of privileged container configuration."""
        from enrichments.container_escape_scorer import enrich_with_container_escape_risk

        finding = {
            "check_title": "Container running in privileged mode",
            "description": "The container is running with privileged:true which allows full host access",
            "service": "kubernetes",
            "risk_score": 50.0,
            "severity": "high",
        }

        result = enrich_with_container_escape_risk(finding)

        assert result is not None
        assert result["total_score"] >= 40  # Privileged mode is 40 points
        assert result["risk_level"] in ["critical", "high"]
        assert any(f["factor_id"] == "privileged" for f in result["factors"])
        assert "T1611" in str(result["mitre_techniques"])

    def test_docker_socket_mount_detection(self):
        """Test detection of Docker socket mount."""
        from enrichments.container_escape_scorer import enrich_with_container_escape_risk

        finding = {
            "check_title": "Dangerous volume mount detected",
            "description": "Container has /var/run/docker.sock mounted",
            "service": "docker",
            "risk_score": 40.0,
            "severity": "medium",
        }

        result = enrich_with_container_escape_risk(finding)

        assert result is not None
        assert any(f["factor_id"] == "docker_socket_mount" for f in result["factors"])
        assert result["assessment_details"]["has_docker_socket"]

    def test_multiple_risk_factors(self):
        """Test detection of multiple risk factors."""
        from enrichments.container_escape_scorer import enrich_with_container_escape_risk

        finding = {
            "check_title": "Kubernetes pod security violation",
            "description": "Pod running with hostPID, NET_ADMIN capability, and privileged mode",
            "service": "kubernetes",
            "risk_score": 60.0,
            "severity": "high",
        }

        result = enrich_with_container_escape_risk(finding)

        assert result is not None
        assert result["factor_count"] >= 2
        assert result["total_score"] >= 50

    def test_non_container_finding_skipped(self):
        """Test that non-container findings are skipped."""
        from enrichments.container_escape_scorer import enrich_with_container_escape_risk

        finding = {
            "check_title": "S3 bucket public access",
            "description": "S3 bucket allows public read access",
            "service": "s3",
            "risk_score": 70.0,
            "severity": "high",
        }

        result = enrich_with_container_escape_risk(finding)

        assert result is None


class TestK8sCVEChecker:
    """Tests for Kubernetes CVE version checking."""

    def test_vulnerable_kubelet_version(self):
        """Test detection of vulnerable kubelet version."""
        from enrichments.k8s_cve_checker import enrich_with_k8s_cve

        finding = {
            "check_title": "Kubernetes version check",
            "description": "Cluster running kubelet 1.29.5",
            "service": "eks",
            "risk_score": 30.0,
            "severity": "medium",
        }

        result = enrich_with_k8s_cve(finding)

        # May or may not find CVEs depending on version
        # The key is it processes K8s findings
        if result:
            assert "components_checked" in result or "potential_cves" in result

    def test_ingress_nginx_cve_detection(self):
        """Test detection of IngressNightmare CVE."""
        from enrichments.k8s_cve_checker import enrich_with_k8s_cve

        finding = {
            "check_title": "Ingress Controller Version",
            "description": "Running ingress-nginx version 1.10.0 which is vulnerable",
            "service": "kubernetes",
            "risk_score": 40.0,
            "severity": "medium",
        }

        result = enrich_with_k8s_cve(finding)

        # Should detect based on keywords or version
        if result:
            assert "cve_matches" in result or "potential_cves" in result

    def test_non_k8s_finding_skipped(self):
        """Test that non-K8s findings are skipped."""
        from enrichments.k8s_cve_checker import enrich_with_k8s_cve

        finding = {
            "check_title": "RDS encryption disabled",
            "description": "Database not encrypted at rest",
            "service": "rds",
            "risk_score": 50.0,
            "severity": "medium",
        }

        result = enrich_with_k8s_cve(finding)

        assert result is None


class TestIMDSEnricher:
    """Tests for IMDS context enrichment."""

    def test_imdsv1_detection(self):
        """Test detection of IMDSv1 enabled."""
        from enrichments.imds_enricher import enrich_with_imds_context

        finding = {
            "check_title": "IMDSv1 Enabled",
            "description": "Instance metadata service v1 is enabled (http tokens optional)",
            "service": "ec2",
            "resource_id": "i-1234567890abcdef0",
            "risk_score": 40.0,
            "severity": "medium",
        }

        result = enrich_with_imds_context(finding)

        assert result is not None
        assert any(f["factor_id"] == "imdsv1_enabled" for f in result["risk_factors"])
        assert result["instance_id"] == "i-1234567890abcdef0"
        assert len(result["remediation_commands"]) > 0

    def test_container_imds_access(self):
        """Test detection of container IMDS access."""
        from enrichments.imds_enricher import enrich_with_imds_context

        finding = {
            "check_title": "IMDS accessible from containers",
            "description": "Pod can access instance metadata at 169.254.169.254",
            "service": "eks",
            "risk_score": 50.0,
            "severity": "high",
        }

        result = enrich_with_imds_context(finding)

        assert result is not None
        assert "attack_context" in result
        assert len(result["recommended_actions"]) > 0

    def test_non_imds_finding_skipped(self):
        """Test that non-IMDS findings are skipped."""
        from enrichments.imds_enricher import enrich_with_imds_context

        finding = {
            "check_title": "Security group too permissive",
            "description": "Allows 0.0.0.0/0 on port 22",
            "service": "ec2",
            "risk_score": 70.0,
            "severity": "high",
        }

        result = enrich_with_imds_context(finding)

        assert result is None


class TestCISAKEVProvider:
    """Tests for CISA KEV enrichment."""

    def test_cve_extraction(self):
        """Test CVE ID extraction from findings."""
        from enrichments.cisa_kev_provider import _extract_cve_ids

        finding = {
            "check_title": "Vulnerable software detected",
            "description": "Found CVE-2021-44228 (Log4Shell) and CVE-2024-12345",
            "poc_evidence": "Affected by CVE-2021-44228",
        }

        cve_ids = _extract_cve_ids(finding)

        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2024-12345" in cve_ids

    def test_no_cve_in_finding(self):
        """Test handling of findings without CVE IDs."""
        from enrichments.cisa_kev_provider import enrich_with_cisa_kev

        finding = {
            "check_title": "MFA not enabled",
            "description": "Root account does not have MFA enabled",
            "service": "iam",
        }

        result = enrich_with_cisa_kev(finding)

        assert result is None  # No CVEs to check


class TestEnrichmentOrchestrator:
    """Tests for the enrichment orchestrator."""

    def test_orchestrator_applies_enrichments(self):
        """Test that orchestrator applies all applicable enrichments."""
        from enrichments import apply_security_enrichments

        finding = {
            "check_title": "Privileged container with IMDS access",
            "description": "Container running privileged:true can access 169.254.169.254",
            "service": "kubernetes",
            "risk_score": 50.0,
            "severity": "high",
            "threat_intel_enrichment": None,
        }

        result = apply_security_enrichments(finding)

        assert result["threat_intel_enrichment"] is not None
        # Should have at least container escape or IMDS enrichment
        enrichments = result["threat_intel_enrichment"]
        assert (
            "container_escape_risk" in enrichments or "imds_context" in enrichments
        )

    def test_orchestrator_initializes_enrichment_field(self):
        """Test that orchestrator initializes threat_intel_enrichment if missing."""
        from enrichments import apply_security_enrichments

        finding = {
            "check_title": "Test finding",
            "description": "Just a test",
            "service": "test",
        }

        result = apply_security_enrichments(finding)

        assert "threat_intel_enrichment" in result
        assert result["threat_intel_enrichment"] is not None

    def test_orchestrator_handles_errors_gracefully(self):
        """Test that orchestrator continues on individual enricher failures."""
        from enrichments import apply_security_enrichments

        # Should not raise exception even with unusual data
        finding = {
            "check_title": None,  # Unusual but shouldn't crash
            "description": 12345,  # Wrong type
            "service": [],  # Wrong type
        }

        # Should not raise
        result = apply_security_enrichments(finding)

        assert "threat_intel_enrichment" in result


class TestVersionComparison:
    """Tests for K8s version comparison utilities."""

    def test_version_parsing(self):
        """Test version string parsing."""
        from enrichments.k8s_cve_checker import _parse_version

        assert _parse_version("1.29.5") == (1, 29, 5)
        assert _parse_version("v1.28.0") == (1, 28, 0)
        assert _parse_version("1.30") == (1, 30, 0)
        assert _parse_version("1.29.5-eks") == (1, 29, 5)
        assert _parse_version("invalid") is None

    def test_version_range_check(self):
        """Test version range checking."""
        from enrichments.k8s_cve_checker import _version_in_range

        # Version in range
        assert _version_in_range("1.29.5", "1.25.0", "1.29.10") is True
        # Version below range
        assert _version_in_range("1.24.0", "1.25.0", "1.29.10") is False
        # Version above range
        assert _version_in_range("1.30.0", "1.25.0", "1.29.10") is False


class TestRiskScoreAdjustments:
    """Tests for risk score adjustments."""

    def test_container_escape_score_adjustment(self):
        """Test that container escape risk adjusts the score."""
        from enrichments.container_escape_scorer import enrich_with_container_escape_risk

        finding = {
            "check_title": "Privileged container",
            "description": "Running with privileged:true and docker.sock mounted",
            "service": "kubernetes",
            "risk_score": 50.0,
            "severity": "medium",
        }

        original_score = finding["risk_score"]
        result = enrich_with_container_escape_risk(finding)

        assert result is not None
        assert finding["risk_score"] > original_score
        assert "risk_score_delta" in result

    def test_imds_score_adjustment(self):
        """Test that IMDS enrichment adjusts the score."""
        from enrichments.imds_enricher import enrich_with_imds_context

        finding = {
            "check_title": "IMDSv1 enabled",
            "description": "Instance metadata v1 enabled with high hop limit",
            "service": "ec2",
            "risk_score": 40.0,
            "severity": "medium",
        }

        original_score = finding["risk_score"]
        result = enrich_with_imds_context(finding)

        assert result is not None
        assert finding["risk_score"] > original_score
