"""Tests for save_to_database in ReportProcessor.

Verifies that the INSERT SQL includes scan_date, first_seen, last_seen
columns and that the values tuple passes the metadata scan_date for each.
"""

from unittest.mock import MagicMock, patch

import pytest


def test_save_to_database_inserts_scan_date_columns(processor, mock_db):
    """The INSERT INTO findings must include scan_date, first_seen, last_seen."""
    mock_conn, mock_cursor = mock_db

    # Wire the mock connection into the processor
    processor.connect_db = MagicMock(return_value=mock_conn)

    metadata = {
        "tool": "prowler",
        "cloud_provider": "aws",
        "scan_date": "2026-04-03T12:00:00",
        "account_id": "123456789012",
    }
    findings = [
        {
            "check_id": "s3_bucket_public",
            "check_title": "S3 Bucket Public Access",
            "severity": "high",
            "status": "open",
            "region": "us-east-1",
            "resource_type": "s3",
            "resource_id": "arn:aws:s3:::my-bucket",
            "resource_name": "my-bucket",
            "account_id": "123456789012",
            "description": "S3 bucket is publicly accessible",
            "remediation": "Block public access",
            "compliance": [],
            "poc_evidence": "{}",
            "poc_verification": "",
            "remediation_commands": [],
            "remediation_code": {},
            "remediation_resources": [],
        }
    ]

    result = processor.save_to_database(metadata, findings, scan_id="prowler-001")

    assert result is True
    mock_conn.commit.assert_called_once()

    # Collect all execute calls to find the INSERT INTO findings statement
    insert_calls = [
        call
        for call in mock_cursor.execute.call_args_list
        if "INSERT INTO findings" in str(call)
    ]
    assert len(insert_calls) >= 1, "Expected at least one INSERT INTO findings call"

    insert_sql = insert_calls[0][0][0]  # First positional arg = SQL string
    insert_values = insert_calls[0][0][1]  # Second positional arg = values tuple

    # Verify the SQL contains the three date columns
    assert "scan_date" in insert_sql, "INSERT SQL must include scan_date column"
    assert "first_seen" in insert_sql, "INSERT SQL must include first_seen column"
    assert "last_seen" in insert_sql, "INSERT SQL must include last_seen column"

    # The last three values in the tuple should be scan_date repeated 3 times
    scan_date_val = metadata["scan_date"]
    assert insert_values[-1] == scan_date_val, (
        f"last_seen should be '{scan_date_val}', got '{insert_values[-1]}'"
    )
    assert insert_values[-2] == scan_date_val, (
        f"first_seen should be '{scan_date_val}', got '{insert_values[-2]}'"
    )
    assert insert_values[-3] == scan_date_val, (
        f"scan_date should be '{scan_date_val}', got '{insert_values[-3]}'"
    )


def test_save_to_database_creates_scan_record(processor, mock_db):
    """When no existing_scan_id, an INSERT INTO scans should occur."""
    mock_conn, mock_cursor = mock_db
    processor.connect_db = MagicMock(return_value=mock_conn)

    metadata = {
        "tool": "cloudsploit",
        "cloud_provider": "aws",
        "scan_date": "2026-04-03T12:00:00",
    }
    findings = []

    result = processor.save_to_database(metadata, findings, scan_id="cs-001")

    assert result is True

    # Should have an INSERT INTO scans call
    scan_insert_calls = [
        call
        for call in mock_cursor.execute.call_args_list
        if "INSERT INTO scans" in str(call)
    ]
    assert len(scan_insert_calls) == 1


def test_save_to_database_updates_existing_scan(processor, mock_db):
    """When existing_scan_id is provided, an UPDATE scans should occur."""
    mock_conn, mock_cursor = mock_db
    processor.connect_db = MagicMock(return_value=mock_conn)

    metadata = {
        "tool": "prowler",
        "cloud_provider": "aws",
        "scan_date": "2026-04-03T12:00:00",
    }
    findings = [
        {
            "check_id": "test",
            "check_title": "Test",
            "severity": "low",
            "status": "open",
            "region": "global",
            "resource_type": "iam",
            "resource_id": "test-resource",
            "resource_name": "test",
            "account_id": "123456789012",
            "description": "Test finding",
            "remediation": "",
            "compliance": [],
            "poc_evidence": "{}",
            "poc_verification": "",
            "remediation_commands": [],
            "remediation_code": {},
            "remediation_resources": [],
        }
    ]

    existing_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    result = processor.save_to_database(
        metadata, findings, scan_id="prowler-002", existing_scan_id=existing_id
    )

    assert result is True

    # Should have an UPDATE scans call instead of INSERT
    update_calls = [
        call
        for call in mock_cursor.execute.call_args_list
        if "UPDATE scans" in str(call)
    ]
    assert len(update_calls) == 1

    # Should NOT have an INSERT INTO scans call
    scan_insert_calls = [
        call
        for call in mock_cursor.execute.call_args_list
        if "INSERT INTO scans" in str(call)
    ]
    assert len(scan_insert_calls) == 0


def test_save_to_database_returns_false_on_no_connection(processor):
    """If connect_db returns None, save_to_database should return False."""
    processor.connect_db = MagicMock(return_value=None)

    metadata = {
        "tool": "prowler",
        "cloud_provider": "aws",
        "scan_date": "2026-04-03T12:00:00",
    }
    result = processor.save_to_database(metadata, [], scan_id="test")

    assert result is False
