"""
Database migrations service.

Runs necessary schema migrations on API startup to ensure
database schema matches ORM models.
"""

from sqlalchemy import text
from sqlalchemy.orm import Session

from logging_config import get_logger

logger = get_logger(__name__)

# Migrations to run on startup (idempotent - safe to run multiple times)
MIGRATIONS = [
    {
        "name": "add_exploitability",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='exploitability'",
        "sql": "ALTER TABLE findings ADD COLUMN exploitability VARCHAR(32) DEFAULT 'likely'",
    },
    {
        "name": "add_asset_criticality",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='asset_criticality'",
        "sql": "ALTER TABLE findings ADD COLUMN asset_criticality VARCHAR(16) DEFAULT 'medium'",
    },
    {
        "name": "add_blast_radius",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='blast_radius'",
        "sql": "ALTER TABLE findings ADD COLUMN blast_radius INTEGER DEFAULT 1",
    },
    {
        "name": "add_recurrence_count",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='recurrence_count'",
        "sql": "ALTER TABLE findings ADD COLUMN recurrence_count INTEGER DEFAULT 1",
    },
    {
        "name": "add_scoring_factors",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='scoring_factors'",
        "sql": "ALTER TABLE findings ADD COLUMN scoring_factors JSONB DEFAULT '{}'",
    },
    {
        "name": "add_threat_intel_enrichment",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='threat_intel_enrichment'",
        "sql": "ALTER TABLE findings ADD COLUMN threat_intel_enrichment JSONB DEFAULT NULL",
    },
    {
        "name": "add_threat_intel_last_checked",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='threat_intel_last_checked'",
        "sql": "ALTER TABLE findings ADD COLUMN threat_intel_last_checked TIMESTAMP",
    },
    {
        "name": "add_canonical_id",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='canonical_id'",
        "sql": "ALTER TABLE findings ADD COLUMN canonical_id VARCHAR(256)",
    },
    {
        "name": "add_tool_sources",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='tool_sources'",
        "sql": "ALTER TABLE findings ADD COLUMN tool_sources JSONB DEFAULT '[]'",
    },
    {
        "name": "add_affected_resources",
        "check": "SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='affected_resources'",
        "sql": "ALTER TABLE findings ADD COLUMN affected_resources JSONB DEFAULT '[]'",
    },
]


def run_migrations(db: Session) -> dict:
    """
    Run all pending database migrations.

    Returns:
        dict with migration results
    """
    results = {
        "migrations_run": 0,
        "migrations_skipped": 0,
        "errors": [],
    }

    for migration in MIGRATIONS:
        try:
            # Check if migration is needed
            result = db.execute(text(migration["check"]))
            exists = result.fetchone() is not None

            if not exists:
                # Run the migration
                db.execute(text(migration["sql"]))
                db.commit()
                results["migrations_run"] += 1
                logger.info(f"Migration applied: {migration['name']}")
            else:
                results["migrations_skipped"] += 1

        except Exception as e:
            results["errors"].append(f"{migration['name']}: {str(e)}")
            logger.error(f"Migration failed: {migration['name']} - {e}")
            db.rollback()

    return results
