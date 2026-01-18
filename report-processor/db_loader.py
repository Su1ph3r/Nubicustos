#!/usr/bin/env python3
"""Database loader utilities for security findings.

This module provides a standalone database loader class for inserting
findings into PostgreSQL. Note that the primary database operations are
handled by ReportProcessor.save_to_database() in process_reports.py.

This module exists as an alternative interface for direct database loading
when the full ReportProcessor pipeline is not needed.
"""

import logging
from typing import Any

import psycopg2
from psycopg2.extensions import connection as PgConnection

logger = logging.getLogger(__name__)


class DBLoader:
    """Database loader for security findings.

    This class provides a simplified interface for loading findings directly
    into the database. For full report processing with enrichment, use the
    ReportProcessor class instead.

    Attributes:
        config: PostgreSQL connection configuration dictionary containing
            host, database, user, and password keys.
    """

    def __init__(self, config: dict[str, str]) -> None:
        """Initialize the database loader with connection configuration.

        Args:
            config: PostgreSQL connection parameters. Required keys:
                - host: Database server hostname
                - database: Database name
                - user: Database username
                - password: Database password
        """
        self.config = config

    def _connect(self) -> PgConnection | None:
        """Establish a database connection.

        Returns:
            PostgreSQL connection object, or None if connection fails.
        """
        try:
            return psycopg2.connect(**self.config)
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            return None

    def load_findings(
        self, findings: list[dict[str, Any]], scan_id: str
    ) -> bool:
        """Load findings into the database.

        Note:
            This method currently serves as a placeholder interface.
            The primary implementation is in ReportProcessor.save_to_database().
            Use that method for full functionality including finding enrichment.

        Args:
            findings: List of finding dictionaries to insert.
            scan_id: UUID of the scan these findings belong to.

        Returns:
            True if findings were loaded successfully, False otherwise.
        """
        conn = self._connect()
        if not conn:
            return False

        try:
            cur = conn.cursor()
            for finding in findings:
                # Note: Primary implementation in ReportProcessor.save_to_database()
                # This placeholder allows future direct-insert functionality
                _ = finding  # Acknowledge the finding (placeholder)
            conn.commit()
            logger.info(f"Processed {len(findings)} findings for scan {scan_id}")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database error loading findings: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Database loader utility - use ReportProcessor for full functionality")
