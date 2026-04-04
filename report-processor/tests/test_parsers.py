"""Tests for report parser methods in ReportProcessor."""

import json
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Prowler (OCSF JSON format)
# ---------------------------------------------------------------------------

PROWLER_OCSF_DATA = [
    {
        "severity_id": 4,
        "severity": "High",
        "class_name": "DetectionFinding",
        "status": "New",
        "status_detail": "S3 bucket has public access enabled",
        "message": "Public access detected on bucket my-bucket",
        "activity_name": "S3 Bucket Public Access",
        "finding_info": {
            "title": "S3 Bucket Public Access Check",
            "desc": "S3 bucket my-bucket has public access enabled.",
        },
        "metadata": {
            "event_code": "s3_bucket_public_access",
        },
        "cloud": {
            "provider": "aws",
            "account": {"uid": "123456789012"},
        },
        "resources": [
            {
                "uid": "arn:aws:s3:::my-bucket",
                "type": "AwsS3Bucket",
                "data": {"metadata": {"BucketName": "my-bucket"}},
            }
        ],
        "unmapped": {
            "remediation": {
                "cli": "aws s3api put-public-access-block --bucket my-bucket",
                "terraform": "resource \"aws_s3_bucket_public_access_block\" {}",
            },
            "compliance": {"framework": "CIS"},
            "related_url": "https://docs.aws.amazon.com/s3/",
            "risk": "Public buckets can be accessed by anyone.",
        },
    }
]


def test_process_prowler_report(processor, tmp_path):
    report_file = tmp_path / "prowler.json"
    report_file.write_text(json.dumps(PROWLER_OCSF_DATA))

    metadata, findings = processor.process_prowler_report(str(report_file))

    assert metadata is not None
    assert metadata["tool"] == "prowler"
    assert "scan_date" in metadata
    assert metadata["cloud_provider"] == "aws"

    assert len(findings) >= 1
    f = findings[0]
    assert f["severity"] in ("info", "low", "medium", "high", "critical")
    assert f["check_title"] or f.get("title")
    assert f["description"]
    assert f["resource_type"]


def test_prowler_empty_report(processor, tmp_path):
    report_file = tmp_path / "prowler_empty.json"
    report_file.write_text(json.dumps([]))

    metadata, findings = processor.process_prowler_report(str(report_file))

    assert metadata is not None
    assert findings == []


# ---------------------------------------------------------------------------
# CloudSploit
# ---------------------------------------------------------------------------

CLOUDSPLOIT_DATA = [
    {
        "plugin": "s3BucketPublicAccess",
        "title": "S3 Bucket Public Access",
        "category": "s3",
        "status": "FAIL",
        "region": "us-east-1",
        "resource": "arn:aws:s3:::my-bucket",
        "message": "S3 bucket my-bucket has public access.",
        "description": "Ensures S3 buckets are not publicly accessible.",
        "compliance": "PCI: 1.2.3",
    },
    {
        "plugin": "iamMfaEnabled",
        "title": "IAM MFA Enabled",
        "category": "iam",
        "status": "WARN",
        "region": "global",
        "resource": "arn:aws:iam::123456789012:root",
        "message": "Root account does not have MFA enabled.",
        "description": "Ensures root account has MFA enabled.",
        "compliance": "",
    },
    {
        "plugin": "ec2InstanceRunning",
        "title": "EC2 Instance Running",
        "category": "ec2",
        "status": "OK",
        "region": "us-east-1",
        "resource": "i-1234567890abcdef0",
        "message": "Instance is running.",
        "description": "Check if instances are running.",
        "compliance": "",
    },
]


def test_process_cloudsploit_report(processor, tmp_path):
    report_file = tmp_path / "cloudsploit.json"
    report_file.write_text(json.dumps(CLOUDSPLOIT_DATA))

    metadata, findings = processor.process_cloudsploit_report(str(report_file))

    assert metadata is not None
    assert metadata["tool"] == "cloudsploit"
    assert "scan_date" in metadata
    assert metadata["cloud_provider"] == "aws"

    # OK status should be filtered out; only FAIL and WARN remain
    assert len(findings) == 2

    for f in findings:
        assert f["severity"] in ("critical", "medium")
        assert f["check_title"]
        assert f["description"]
        assert f["resource_type"]


def test_cloudsploit_ok_only_yields_no_findings(processor, tmp_path):
    data = [
        {
            "plugin": "check",
            "title": "Check",
            "category": "ec2",
            "status": "OK",
            "region": "us-east-1",
            "resource": "i-123",
            "message": "All good",
            "description": "desc",
            "compliance": "",
        }
    ]
    report_file = tmp_path / "cloudsploit_ok.json"
    report_file.write_text(json.dumps(data))

    metadata, findings = processor.process_cloudsploit_report(str(report_file))

    assert metadata is not None
    assert findings == []


# ---------------------------------------------------------------------------
# TruffleHog (JSONL — newline-delimited JSON)
# ---------------------------------------------------------------------------

TRUFFLEHOG_DATA = [
    {
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "config/secrets.yaml",
                    "line": 42,
                }
            }
        },
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "DetectorName": "AWS",
        "DetectorType": 1,
        "Verified": True,
    },
    {
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "src/app.py",
                    "line": 10,
                }
            }
        },
        "Raw": "ghp_abcdefghij1234567890",
        "DetectorName": "GitHub",
        "DetectorType": 2,
        "Verified": False,
    },
]


def test_process_trufflehog_report(processor, tmp_path):
    # TruffleHog writes newline-delimited JSON
    report_file = tmp_path / "trufflehog.json"
    lines = [json.dumps(item) for item in TRUFFLEHOG_DATA]
    report_file.write_text("\n".join(lines))

    metadata, findings = processor.process_trufflehog_report(str(report_file))

    assert metadata is not None
    assert metadata["tool"] == "trufflehog"
    assert "scan_date" in metadata
    assert metadata["cloud_provider"] == "secrets"

    assert len(findings) == 2

    # Verified AWS secret should be critical
    aws_finding = findings[0]
    assert aws_finding["severity"] == "critical"
    assert aws_finding["resource_type"] == "secret"
    assert "secrets.yaml" in aws_finding["resource_id"]
    assert aws_finding["description"]
    assert aws_finding["check_title"]

    # Unverified GitHub secret should be high (cloud provider detector)
    gh_finding = findings[1]
    assert gh_finding["severity"] == "high"


def test_trufflehog_skips_log_lines(processor, tmp_path):
    log_line = {"level": "info", "msg": "scanning filesystem"}
    finding_line = TRUFFLEHOG_DATA[0]
    report_file = tmp_path / "trufflehog_logs.json"
    report_file.write_text(
        json.dumps(log_line) + "\n" + json.dumps(finding_line) + "\n"
    )

    metadata, findings = processor.process_trufflehog_report(str(report_file))

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------

GITLEAKS_DATA = [
    {
        "Description": "AWS Access Key ID",
        "File": "config/aws.env",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "Match": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "RuleID": "aws-access-key-id",
        "StartLine": 5,
        "EndLine": 5,
        "Fingerprint": "config/aws.env:aws-access-key-id:5",
    },
    {
        "Description": "Generic API Key",
        "File": "src/config.js",
        "Secret": "some-generic-api-key-value",
        "Match": "API_KEY=some-generic-api-key-value",
        "RuleID": "generic-api-key",
        "StartLine": 12,
        "EndLine": 12,
        "Fingerprint": "src/config.js:generic-api-key:12",
    },
]


def test_process_gitleaks_report(processor, tmp_path):
    report_file = tmp_path / "gitleaks.json"
    report_file.write_text(json.dumps(GITLEAKS_DATA))

    metadata, findings = processor.process_gitleaks_report(str(report_file))

    assert metadata is not None
    assert metadata["tool"] == "gitleaks"
    assert "scan_date" in metadata
    assert metadata["cloud_provider"] == "secrets"

    assert len(findings) == 2

    # aws-access-key-id is in high_severity_rules
    aws_finding = findings[0]
    assert aws_finding["severity"] == "high"
    assert aws_finding["resource_type"] == "secret"
    assert "aws.env" in aws_finding["resource_id"]
    assert aws_finding["description"]
    assert aws_finding["check_title"]

    # generic-api-key is medium
    generic_finding = findings[1]
    assert generic_finding["severity"] == "medium"


def test_gitleaks_empty_array(processor, tmp_path):
    report_file = tmp_path / "gitleaks_empty.json"
    report_file.write_text(json.dumps([]))

    metadata, findings = processor.process_gitleaks_report(str(report_file))

    assert metadata is not None
    assert findings == []


# ---------------------------------------------------------------------------
# Checkov
# ---------------------------------------------------------------------------

CHECKOV_DATA = {
    "check_type": "terraform",
    "results": {
        "passed_checks": [
            {
                "check_id": "CKV_AWS_18",
                "check_name": "Ensure the S3 bucket has access logging enabled",
                "severity": "LOW",
                "resource": "aws_s3_bucket.example",
                "resource_address": "aws_s3_bucket.example",
                "file_path": "/main.tf",
                "file_line_range": [1, 10],
            }
        ],
        "failed_checks": [
            {
                "check_id": "CKV_AWS_19",
                "check_name": "Ensure the S3 bucket has server-side encryption",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.data",
                "resource_address": "aws_s3_bucket.data",
                "file_path": "/main.tf",
                "file_line_range": [11, 20],
                "guideline": "Enable SSE-S3 or SSE-KMS on the bucket.",
                "code_block": "",
                "check_class": "checkov.terraform",
            },
            {
                "check_id": "CKV_AWS_145",
                "check_name": "Ensure S3 bucket is encrypted with KMS",
                "severity": None,
                "resource": "aws_s3_bucket.logs",
                "resource_address": "aws_s3_bucket.logs",
                "file_path": "/logging.tf",
                "file_line_range": [1, 8],
                "guideline": "",
                "code_block": "",
                "check_class": "checkov.terraform",
            },
        ],
    },
}


def test_process_checkov_report(processor, tmp_path):
    report_file = tmp_path / "checkov.json"
    report_file.write_text(json.dumps(CHECKOV_DATA))

    metadata, findings = processor.process_checkov_report(str(report_file))

    assert metadata is not None
    assert metadata["tool"] == "checkov"
    assert "scan_date" in metadata
    assert metadata["cloud_provider"] == "iac"

    # Only failed checks should be imported (passed are ignored)
    assert len(findings) == 2

    f = findings[0]
    assert f["severity"] == "high"
    assert f["check_id"] == "CKV_AWS_19"
    assert f["description"]
    assert f["resource_type"]

    # severity=None should fall back to medium
    f_none_sev = findings[1]
    assert f_none_sev["severity"] == "medium"


def test_checkov_no_failed_checks(processor, tmp_path):
    data = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "S3 logging",
                    "severity": "LOW",
                    "resource": "aws_s3_bucket.ok",
                    "resource_address": "aws_s3_bucket.ok",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 5],
                }
            ],
            "failed_checks": [],
        },
    }
    report_file = tmp_path / "checkov_pass.json"
    report_file.write_text(json.dumps(data))

    metadata, findings = processor.process_checkov_report(str(report_file))

    assert metadata is not None
    assert findings == []
