"""Tests for settings endpoint with webhook validation."""

from models.database import UserSetting


class TestWebhookValidation:
    """Tests for webhook URL validation in settings updates."""

    def _create_webhook_setting(self, db_session):
        """Helper to create a webhook_url setting in the test DB."""
        setting = UserSetting(
            setting_key="webhook_url",
            setting_value=None,
            category="notifications",
            description="Webhook URL for notifications",
        )
        db_session.add(setting)
        db_session.commit()
        db_session.refresh(setting)
        return setting

    def test_webhook_url_requires_https(self, client, db_session):
        """HTTP webhook URLs should be rejected."""
        self._create_webhook_setting(db_session)
        response = client.put(
            "/api/settings/webhook_url",
            json={"value": "http://hooks.slack.com/xxx"},
        )
        assert response.status_code == 400
        assert "HTTPS" in response.json()["detail"]

    def test_webhook_url_accepts_https(self, client, db_session):
        """HTTPS webhook URLs should be accepted."""
        self._create_webhook_setting(db_session)
        response = client.put(
            "/api/settings/webhook_url",
            json={"value": "https://hooks.slack.com/xxx"},
        )
        assert response.status_code == 200

    def test_webhook_url_null_accepted(self, client, db_session):
        """Null/empty webhook URLs should be accepted (clearing the setting)."""
        self._create_webhook_setting(db_session)
        response = client.put(
            "/api/settings/webhook_url",
            json={"value": None},
        )
        assert response.status_code == 200

    def test_webhook_url_invalid_hostname(self, client, db_session):
        """URLs without hostname should be rejected."""
        self._create_webhook_setting(db_session)
        response = client.put(
            "/api/settings/webhook_url",
            json={"value": "https://"},
        )
        assert response.status_code == 400
