"""Integration tests for report processing pipeline.

These tests verify that the report processor can run within the API container
with all required dependencies and writable paths.
"""

import pytest
import sys
import os


class TestReportProcessorIntegration:
    """Test that report processor can be imported and initialized in API container."""

    def test_report_processor_dependencies_available(self):
        """Verify all report processor dependencies are installed."""
        # These imports must succeed for report processing to work
        import pandas
        import numpy
        import jinja2
        import tabulate
        import yaml
        import click
        import colorama

    def test_report_processor_importable(self):
        """Verify ReportProcessor can be imported from report-processor module."""
        # Add report-processor to path (as done in scans.py)
        sys.path.insert(0, "/app/report-processor")

        try:
            from process_reports import ReportProcessor
            # Verify it can be instantiated
            processor = ReportProcessor()
            assert processor is not None
        except ImportError as e:
            pytest.fail(f"Could not import ReportProcessor: {e}")
        finally:
            # Clean up path
            if "/app/report-processor" in sys.path:
                sys.path.remove("/app/report-processor")

    def test_processed_directory_writable(self):
        """Verify /processed directory exists and is writable."""
        processed_dir = "/processed"

        # Check directory exists
        assert os.path.isdir(processed_dir), f"{processed_dir} directory does not exist"

        # Check it's writable
        test_file = os.path.join(processed_dir, ".write_test")
        try:
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except (IOError, OSError) as e:
            pytest.fail(f"{processed_dir} is not writable: {e}")

    def test_reports_directory_readable(self):
        """Verify /reports directory exists and is readable."""
        reports_dir = "/reports"

        assert os.path.isdir(reports_dir), f"{reports_dir} directory does not exist"
        # Try to list contents
        try:
            os.listdir(reports_dir)
        except (IOError, OSError) as e:
            pytest.fail(f"{reports_dir} is not readable: {e}")
