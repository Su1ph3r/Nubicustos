"""Audit logging service for tracking destructive and sensitive operations."""

import logging

from sqlalchemy.orm import Session

from models.database import AuditHistory

logger = logging.getLogger(__name__)


def log_audit(
    db: Session,
    action: str,
    details: dict = None,
    scan_id=None,
    performed_by: str = "api",
):
    """Write an audit log entry.

    This function is designed to never raise exceptions so that audit logging
    failures do not break the request that triggered them.

    Args:
        db: SQLAlchemy database session.
        action: Short action identifier (e.g. "scan_created", "database_purged").
        details: Optional JSON-serialisable dict with contextual information.
        scan_id: Optional UUID of the related scan.
        performed_by: Identifier for the actor performing the action.
    """
    try:
        with db.begin_nested():
            entry = AuditHistory(
                action=action,
                details=details,
                scan_id=scan_id,
                performed_by=performed_by,
            )
            db.add(entry)
        db.flush()
    except Exception:
        logger.exception("Failed to write audit log entry for action=%s", action)
