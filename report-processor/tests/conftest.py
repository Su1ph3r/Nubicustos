"""Shared fixtures for report-processor tests."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the report-processor package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def processor():
    """Create a ReportProcessor with mocked DB connection and env vars."""
    with patch.dict(
        "os.environ",
        {
            "DB_PASSWORD": "testpass",
            "DB_HOST": "localhost",
            "DB_NAME": "test_db",
            "DB_USER": "test_user",
        },
    ), patch("process_reports.Path.mkdir"):
        from process_reports import ReportProcessor

        rp = ReportProcessor()
        # Prevent any real DB connections during parser tests
        rp.connect_db = MagicMock(return_value=None)
        return rp


@pytest.fixture
def mock_db():
    """Provide a mock psycopg2 connection and cursor for save_to_database tests."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None  # No existing finding by default

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    return mock_conn, mock_cursor
