"""Database operations: connection, saving findings, and report generation."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import psycopg2
import psycopg2.extensions
from psycopg2.extras import Json

from parsers.utils import generate_canonical_id

# Import severity scoring module
try:
    from severity_scoring import calculate_risk_score, enrich_finding_with_scoring
except ImportError:
    def enrich_finding_with_scoring(finding):
        finding["risk_score"] = 50.0
        finding["cvss_score"] = 5.0
        finding["exploitation_likelihood"] = "likely"
        return finding

    def calculate_risk_score(finding, base_severity=None):
        return 50.0, "medium", {}

# ---------------------------------------------------------------------------
# Model-derived SQL (Unit 6): Try to import Finding model for column validation
# ---------------------------------------------------------------------------
try:
    import sys
    # Add api directory to path for model import
    _api_dir = str(Path(__file__).resolve().parent.parent / "api")
    if _api_dir not in sys.path:
        sys.path.insert(0, _api_dir)
    from models.database import Finding
    _FINDING_MODEL_AVAILABLE = True
except ImportError:
    _FINDING_MODEL_AVAILABLE = False


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Column mapping: single source of truth for the INSERT statement
# ---------------------------------------------------------------------------
# Columns we write to, in order. Derived from the model when available.
if _FINDING_MODEL_AVAILABLE:
    _MODEL_COLUMNS = {c.name for c in Finding.__table__.columns if c.name != 'id'}
else:
    _MODEL_COLUMNS = None

# The ordered mapping from finding dict key -> DB column name
FINDING_INSERT_MAP = [
    ("finding_id", "finding_id"),
    ("scan_id", "scan_id"),
    ("tool", "tool"),
    ("cloud_provider", "cloud_provider"),
    ("account_id", "account_id"),
    ("region", "region"),
    ("resource_type", "resource_type"),
    ("resource_id", "resource_id"),
    ("resource_name", "resource_name"),
    ("severity", "severity"),
    ("status", "status"),
    ("title", "title"),
    ("description", "description"),
    ("remediation", "remediation"),
    ("compliance", "compliance_frameworks"),
    ("metadata_json", "metadata"),
    ("poc_evidence", "poc_evidence"),
    ("poc_verification", "poc_verification"),
    ("remediation_commands", "remediation_commands"),
    ("remediation_code", "remediation_code"),
    ("remediation_resources", "remediation_resources"),
    ("canonical_id", "canonical_id"),
    ("tool_sources", "tool_sources"),
    ("affected_resources", "affected_resources"),
    ("risk_score", "risk_score"),
    ("cvss_score", "cvss_score"),
    ("exploitation_likelihood", "exploitability"),
    ("scan_date", "scan_date"),
    ("first_seen", "first_seen"),
    ("last_seen", "last_seen"),
]

# Validate column mapping against the model at import time
if _FINDING_MODEL_AVAILABLE:
    _insert_cols = {col_name for _, col_name in FINDING_INSERT_MAP}
    _missing = _insert_cols - _MODEL_COLUMNS - {"metadata"}  # metadata is aliased
    if _missing:
        logger.warning(f"FINDING_INSERT_MAP references columns not in Finding model: {_missing}")


def _build_finding_values(finding, metadata, scan_id, canonical_id, finding_unique_id):
    """Build values tuple matching FINDING_INSERT_MAP column order."""
    return (
        finding_unique_id,
        scan_id,
        metadata["tool"],
        metadata.get("cloud_provider", "unknown"),
        finding.get("account_id", metadata.get("account_id", "unknown")),
        finding.get("region", "global"),
        finding.get("resource_type", ""),
        finding.get("resource_id", ""),
        finding.get("resource_name", finding.get("resource_id", "")),
        finding.get("severity", "unknown").lower(),
        finding.get("status", "open").lower()
        if finding.get("status", "FAIL") != "PASS"
        else "closed",
        finding.get("check_title", finding.get("type", "")),
        finding.get("description", ""),
        finding.get("remediation", ""),
        Json(finding.get("compliance", [])),
        Json(finding),
        finding.get("poc_evidence", ""),
        finding.get("poc_verification", ""),
        Json(finding.get("remediation_commands", [])),
        Json(finding.get("remediation_code", {})),
        Json(finding.get("remediation_resources", [])),
        canonical_id,
        Json([metadata["tool"]]),
        Json(finding.get("affected_resources", [])),
        finding.get("risk_score", 50.0),
        finding.get("cvss_score", 5.0),
        finding.get("exploitation_likelihood", "likely"),
        metadata.get("scan_date"),
        metadata.get("scan_date"),
        metadata.get("scan_date"),
    )


# ---------------------------------------------------------------------------
# Dead-letter queue (Unit 5)
# ---------------------------------------------------------------------------
_DEFAULT_DEAD_LETTER_DIR = "/reports/dead-letter/"


def _write_dead_letter(metadata, findings, error, dead_letter_dir=_DEFAULT_DEAD_LETTER_DIR):
    """Persist a failed batch to the dead-letter directory for later retry.

    Args:
        metadata: Scan metadata dict.
        findings: List of finding dicts that could not be saved.
        error: The exception or error string that caused the failure.
        dead_letter_dir: Directory to write dead-letter files into. None to suppress.
    """
    if dead_letter_dir is None:
        return
    dl_dir = Path(dead_letter_dir)
    dl_dir.mkdir(parents=True, exist_ok=True)

    tool = metadata.get("tool", "unknown")
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    filename = f"{tool}_{timestamp}.json"
    filepath = dl_dir / filename

    payload = {
        "metadata": metadata,
        "findings": findings,
        "error": str(error),
        "timestamp": datetime.utcnow().isoformat(),
        "retry_count": 0,
    }

    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    logger.warning(f"Wrote {len(findings)} findings to dead-letter: {filepath}")
    return filepath


def connect_db(db_config) -> psycopg2.extensions.connection | None:
    """Connect to PostgreSQL database.

    Args:
        db_config: Dictionary with host, database, user, password keys.

    Returns:
        PostgreSQL connection object, or None if connection fails.
    """
    try:
        return psycopg2.connect(**db_config)
    except psycopg2.OperationalError as e:
        logger.error(f"Database connection failed (operational error): {e}")
        return None
    except psycopg2.Error as e:
        logger.error(f"Database connection failed: {e}")
        return None


def save_to_database(db_config, metadata, findings, scan_id, existing_scan_id=None, conn=None,
                     dead_letter_dir=_DEFAULT_DEAD_LETTER_DIR):
    """Save processed findings to database.

    Args:
        db_config: Database configuration dict.
        metadata: Scan metadata dict.
        findings: List of finding dicts.
        scan_id: Internal scan identifier (tool-specific).
        existing_scan_id: Optional UUID of an existing scan to link findings to.
        conn: Optional pre-existing database connection. If None, a new
              connection is created from db_config.
        dead_letter_dir: Directory for dead-letter queue files on failure.
    """
    owns_conn = conn is None
    if owns_conn:
        conn = connect_db(db_config)
    if not conn:
        return False

    try:
        cur = conn.cursor()

        # Apply CVSS-style severity scoring to all findings
        for finding in findings:
            enrich_finding_with_scoring(finding)

        # Apply security enrichments (CISA KEV, K8s CVE, container escape, IMDS)
        try:
            from enrichments import apply_security_enrichments

            for finding in findings:
                apply_security_enrichments(finding)
            logger.info(f"Applied security enrichments to {len(findings)} findings")
        except ImportError as e:
            logger.warning(f"Security enrichments not available (skipping): {e}")
        except Exception as e:
            logger.error(f"Security enrichment pipeline failed: {e}")

        # Count findings by adjusted severity (after scoring)
        critical_count = len(
            [f for f in findings if f.get("severity", "").lower() == "critical"]
        )
        high_count = len([f for f in findings if f.get("severity", "").lower() == "high"])
        medium_count = len([f for f in findings if f.get("severity", "").lower() == "medium"])
        low_count = len([f for f in findings if f.get("severity", "").lower() == "low"])

        # Use existing scan_id if provided, otherwise generate new UUID
        if existing_scan_id:
            db_scan_id = existing_scan_id
            cur.execute(
                """
                UPDATE scans SET
                    completed_at = %s,
                    status = 'completed',
                    total_findings = total_findings + %s,
                    critical_findings = critical_findings + %s,
                    high_findings = high_findings + %s,
                    medium_findings = medium_findings + %s,
                    low_findings = low_findings + %s
                WHERE scan_id = %s
            """,
                (
                    metadata["scan_date"],
                    len(findings),
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    db_scan_id,
                ),
            )
            logger.info(f"Updated existing scan {db_scan_id} with {len(findings)} findings")
        else:
            import uuid

            db_scan_id = str(uuid.uuid4())

            cur.execute(
                """
                INSERT INTO scans (
                    scan_id, scan_type, target, tool,
                    started_at, completed_at, status,
                    total_findings, critical_findings, high_findings,
                    medium_findings, low_findings, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    db_scan_id,
                    "security_audit",
                    metadata.get("cloud_provider", "unknown"),
                    metadata["tool"],
                    metadata["scan_date"],
                    metadata["scan_date"],
                    "completed",
                    len(findings),
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    Json(metadata),
                ),
            )

        # Insert findings with cross-tool deduplication using canonical_id
        for finding in findings:
            canonical_id = generate_canonical_id(finding)

            finding_unique_id = canonical_id

            cur.execute(
                """
                SELECT id, tool_sources, affected_resources FROM findings
                WHERE finding_id = %s
            """,
                (finding_unique_id,),
            )
            existing = cur.fetchone()

            if existing:
                existing_id, existing_tools, existing_resources = existing
                existing_tools = existing_tools if isinstance(existing_tools, list) else []
                existing_resources = existing_resources if existing_resources else []

                new_tool = metadata["tool"]
                if new_tool not in existing_tools:
                    existing_tools.append(new_tool)

                new_resources = finding.get("affected_resources", [])
                existing_resource_ids = {
                    r.get("id") for r in existing_resources if isinstance(r, dict)
                }
                for res in new_resources:
                    if isinstance(res, dict) and res.get("id") not in existing_resource_ids:
                        existing_resources.append(res)

                cur.execute(
                    """
                    UPDATE findings SET
                        tool_sources = %s,
                        affected_resources = %s,
                        last_seen = NOW(),
                        scan_id = %s,
                        risk_score = %s,
                        cvss_score = %s,
                        exploitability = %s,
                        severity = %s
                    WHERE id = %s
                """,
                    (
                        Json(existing_tools),
                        Json(existing_resources),
                        db_scan_id,
                        finding.get("risk_score", 50.0),
                        finding.get("cvss_score", 5.0),
                        finding.get("exploitation_likelihood", "likely"),
                        finding.get("severity", "medium").lower(),
                        existing_id,
                    ),
                )
            else:
                columns = [col_name for _, col_name in FINDING_INSERT_MAP]
                placeholders = ", ".join(["%s"] * len(columns))
                insert_sql = f"INSERT INTO findings ({', '.join(columns)}) VALUES ({placeholders})"

                values = _build_finding_values(
                    finding, metadata, db_scan_id, canonical_id, finding_unique_id
                )
                cur.execute(insert_sql, values)

        conn.commit()
        logger.info(f"Saved {len(findings)} findings to database for scan {db_scan_id}")
        return True

    except Exception as e:
        logger.error(f"Error saving to database: {e}")
        try:
            conn.rollback()
        except Exception as rollback_err:
            logger.error(f"Rollback also failed: {rollback_err}")
        _write_dead_letter(metadata, findings, e, dead_letter_dir)
        return False
    finally:
        if owns_conn:
            conn.close()


def retry_dead_letters(db_config, dead_letter_dir=_DEFAULT_DEAD_LETTER_DIR):
    """Retry all dead-lettered finding batches.

    Scans the dead-letter directory for JSON files, attempts to re-save each
    batch via ``save_to_database``, and returns a summary of results.

    Args:
        db_config: Database configuration dict.
        dead_letter_dir: Path to the dead-letter directory.

    Returns:
        dict with keys ``retried``, ``succeeded``, ``failed``.
    """
    dl_dir = Path(dead_letter_dir)
    summary = {"retried": 0, "succeeded": 0, "failed": 0}

    if not dl_dir.exists():
        logger.info(f"Dead-letter directory does not exist: {dl_dir}")
        return summary

    dl_files = sorted(dl_dir.glob("*.json"))
    if not dl_files:
        logger.info("No dead-letter files found")
        return summary

    for dl_file in dl_files:
        summary["retried"] += 1
        try:
            with open(dl_file, "r") as f:
                payload = json.load(f)

            metadata = payload["metadata"]
            findings = payload["findings"]
            scan_id = f"retry_{metadata.get('tool', 'unknown')}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

            # Suppress dead-letter writing during retries to avoid recursive growth
            success = save_to_database(
                db_config, metadata, findings, scan_id,
                dead_letter_dir=None,
            )

            if success:
                summary["succeeded"] += 1
                dl_file.unlink()
                logger.info(f"Retry succeeded, removed dead-letter file: {dl_file}")
            else:
                summary["failed"] += 1
                # Increment retry_count in the file
                payload["retry_count"] = payload.get("retry_count", 0) + 1
                with open(dl_file, "w") as f:
                    json.dump(payload, f, indent=2, default=str)
                logger.error(f"Retry failed for dead-letter file: {dl_file} (retry_count={payload['retry_count']})")

        except Exception as e:
            summary["failed"] += 1
            logger.error(f"Error retrying dead-letter file {dl_file}: {e}")

    logger.info(f"Dead-letter retry summary: {summary}")
    return summary


def generate_unified_report(db_config, processed_dir):
    """Generate unified HTML report from all findings.

    Args:
        db_config: Database configuration dict.
        processed_dir: Path to the processed output directory.
    """
    conn = connect_db(db_config)
    if not conn:
        return

    try:
        query = """
            SELECT f.*, s.tool, s.target as cloud_provider
            FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            WHERE s.started_at > NOW() - INTERVAL '7 days'
            ORDER BY f.severity DESC, f.finding_id
        """

        df = pd.read_sql(query, conn)

        summary = {
            "total_findings": len(df),
            "critical": len(df[df["severity"].str.lower() == "critical"]),
            "high": len(df[df["severity"].str.lower() == "high"]),
            "medium": len(df[df["severity"].str.lower() == "medium"]),
            "low": len(df[df["severity"].str.lower() == "low"]),
            "by_region": df.groupby("region").size().to_dict(),
            "by_tool": df.groupby("tool").size().to_dict(),
        }

        processed_dir = Path(processed_dir)
        summary_path = (
            processed_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Generated unified report with {summary['total_findings']} findings")

    except Exception as e:
        logger.error(f"Error generating unified report: {e}")
    finally:
        conn.close()


def register_scan_files(db_config, scan_id: str, tool: str, file_paths: list):
    """Register report files associated with a scan in the scan_files table.

    Args:
        db_config: Database configuration dict.
        scan_id: UUID of the scan.
        tool: Tool name (e.g., 'prowler', 'scoutsuite').
        file_paths: List of file paths (Path objects or strings).
    """
    conn = connect_db(db_config)
    if not conn:
        logger.warning("Could not register scan files - database connection failed")
        return

    try:
        cur = conn.cursor()
        for file_path in file_paths:
            path = Path(file_path)
            if not path.exists():
                continue
            try:
                file_stat = path.stat()
                file_type = path.suffix.lstrip(".") or "unknown"
                cur.execute(
                    """
                    INSERT INTO scan_files (scan_id, tool, file_path, file_type, file_size_bytes)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id, file_path) DO UPDATE SET
                        file_size_bytes = EXCLUDED.file_size_bytes
                    """,
                    (scan_id, tool, str(path), file_type, file_stat.st_size),
                )
            except Exception as e:
                logger.warning(f"Failed to register file {path}: {e}")
        conn.commit()
        logger.info(f"Registered {len(file_paths)} files for scan {scan_id}, tool {tool}")
    except Exception as e:
        logger.error(f"Failed to register scan files: {e}")
        conn.rollback()
    finally:
        conn.close()
