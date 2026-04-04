"""Tests for audit logging on destructive operations."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from models.database import AuditHistory, UserSetting


class TestAuditLogging:
    """Test cases for audit log entries created by destructive operations."""

    def test_scan_creation_creates_audit_entry(
        self, client: TestClient, db_session: Session
    ) -> None:
        """POST /scans should create an audit entry with action='scan_created'."""
        response = client.post(
            "/api/scans",
            json={"profile": "quick", "provider": "aws", "dry_run": True},
        )

        assert response.status_code == 200
        data = response.json()
        scan_id = data["scan_id"]

        entries = (
            db_session.query(AuditHistory)
            .filter(AuditHistory.action == "scan_created")
            .all()
        )
        assert len(entries) == 1
        assert entries[0].details["scan_id"] == scan_id
        assert entries[0].performed_by == "api"

    def test_database_purge_creates_audit_entry(
        self, client: TestClient, db_session: Session
    ) -> None:
        """DELETE /database/purge?confirm=true should create an audit entry."""
        response = client.delete("/api/database/purge?confirm=true")

        assert response.status_code == 200

        entries = (
            db_session.query(AuditHistory)
            .filter(AuditHistory.action == "database_purged")
            .all()
        )
        assert len(entries) == 1
        assert "tables_cleared" in entries[0].details

    def test_setting_update_creates_audit_entry(
        self, client: TestClient, db_session: Session
    ) -> None:
        """PUT /settings/{key} should create an audit entry with action='setting_updated'."""
        # Seed a setting so the PUT has something to update
        setting = UserSetting(
            setting_key="theme",
            setting_value="dark",
            category="display",
            description="UI theme",
        )
        db_session.add(setting)
        db_session.commit()

        response = client.put("/api/settings/theme", json={"value": "light"})

        assert response.status_code == 200

        entries = (
            db_session.query(AuditHistory)
            .filter(AuditHistory.action == "setting_updated")
            .all()
        )
        assert len(entries) == 1
        assert entries[0].details["key"] == "theme"
        assert entries[0].details["category"] == "display"

    def test_audit_service_log_audit(self, db_session: Session) -> None:
        """log_audit should write an AuditHistory row with the given action and details."""
        from services.audit_service import log_audit

        log_audit(db_session, "scan_cancelled", {"scan_id": "abc-123"})

        entries = (
            db_session.query(AuditHistory)
            .filter(AuditHistory.action == "scan_cancelled")
            .all()
        )
        assert len(entries) == 1
        assert entries[0].details["scan_id"] == "abc-123"
        assert entries[0].performed_by == "api"

    def test_audit_service_does_not_raise_on_error(self, db_session: Session) -> None:
        """log_audit should silently handle errors without raising."""
        from services.audit_service import log_audit

        # Close the session to force an error on commit
        db_session.close()
        # This must not raise
        log_audit(db_session, "should_fail", {"test": True})
