"""
Notification Service for Scan Completions.

This module provides notification dispatch for scan completion events.
It integrates with the user settings system to determine which channels
are enabled and sends notifications accordingly.

Usage:
    from services.notification_service import send_scan_notification

    await send_scan_notification(db, scan_id, "scan_complete", summary)
"""

import ipaddress
import logging
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from sqlalchemy.orm import Session

from models.database import UserSetting

logger = logging.getLogger(__name__)


class _SSRFSafeAdapter(HTTPAdapter):
    """HTTP adapter that validates resolved IPs to prevent SSRF via DNS rebinding."""

    def send(self, request, **kwargs):
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        hostname = parsed.hostname
        if hostname:
            resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for _, _, _, _, addr in resolved:
                ip = ipaddress.ip_address(addr[0])
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise ValueError(f"Request blocked: {hostname} resolves to private IP {addr[0]}")
        return super().send(request, **kwargs)


def _get_safe_session():
    """Create an HTTP session with SSRF protection at connect time."""
    session = requests.Session()
    session.mount("https://", _SSRFSafeAdapter())
    session.mount("http://", _SSRFSafeAdapter())
    return session


def _validate_webhook_url(url: str) -> bool:
    """Validate that a webhook URL is not targeting internal/private networks."""
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            logger.warning(f"Webhook URL has unsupported scheme: {parsed.scheme}")
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        # Resolve hostname and check for private IP ranges
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, addr in resolved:
            ip = ipaddress.ip_address(addr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                logger.warning(f"Webhook URL resolves to private/internal IP: {addr[0]}")
                return False
        return True
    except (socket.gaierror, ValueError) as e:
        logger.warning(f"Webhook URL validation failed for {url}: {e}")
        return False


def _get_setting_value(db: Session, key: str, default=None):
    """Get a setting value from the database."""
    setting = db.query(UserSetting).filter(UserSetting.setting_key == key).first()
    if setting and setting.setting_value:
        value = setting.setting_value
        # Handle JSON null values
        if value in ("null", None, "None"):
            return default
        return value
    return default


def _send_slack_notification(webhook_url: str, summary: dict, scan_id: str = None) -> bool:
    """Send notification to Slack."""
    if not webhook_url or webhook_url in ("null", "None", ""):
        return False
    if not _validate_webhook_url(webhook_url):
        raise ValueError(f"Webhook URL failed SSRF validation for host: {urlparse(webhook_url).hostname}")

    # Calculate total
    total = sum([
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
    ])

    message = {
        "text": f"Cloud Security Audit Complete - {total} findings",
        "attachments": [
            {
                "color": "danger" if summary.get("critical", 0) > 0 else (
                    "warning" if summary.get("high", 0) > 0 else "good"
                ),
                "fields": [
                    {"title": "Critical", "value": str(summary.get("critical", 0)), "short": True},
                    {"title": "High", "value": str(summary.get("high", 0)), "short": True},
                    {"title": "Medium", "value": str(summary.get("medium", 0)), "short": True},
                    {"title": "Low", "value": str(summary.get("low", 0)), "short": True},
                ],
                "footer": f"Scan ID: {scan_id}" if scan_id else "Nubicustos",
                "ts": int(datetime.utcnow().timestamp()),
            }
        ],
    }

    try:
        session = _get_safe_session()
        response = session.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info(f"Slack notification sent for scan {scan_id}")
        return True
    except requests.exceptions.HTTPError as e:
        logger.error(f"Slack webhook returned error ({e.response.status_code}): {e}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Slack notification: {e}")
        raise


def _send_teams_notification(webhook_url: str, summary: dict, scan_id: str = None) -> bool:
    """Send notification to Microsoft Teams."""
    if not webhook_url or webhook_url in ("null", "None", ""):
        return False
    if not _validate_webhook_url(webhook_url):
        raise ValueError(f"Webhook URL failed SSRF validation for host: {urlparse(webhook_url).hostname}")

    # Calculate total
    total = sum([
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
    ])

    # Determine card color based on severity
    if summary.get("critical", 0) > 0:
        theme_color = "FF0000"
    elif summary.get("high", 0) > 0:
        theme_color = "FFA500"
    elif summary.get("medium", 0) > 0:
        theme_color = "FFFF00"
    else:
        theme_color = "00FF00"

    message = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Cloud Security Audit Complete - {total} findings",
        "sections": [
            {
                "activityTitle": "Cloud Security Audit Complete",
                "activitySubtitle": f"Scan ID: {scan_id}" if scan_id else "Security audit completed",
                "facts": [
                    {"name": "Critical", "value": str(summary.get("critical", 0))},
                    {"name": "High", "value": str(summary.get("high", 0))},
                    {"name": "Medium", "value": str(summary.get("medium", 0))},
                    {"name": "Low", "value": str(summary.get("low", 0))},
                    {"name": "Total", "value": str(total)},
                ],
                "markdown": True,
            }
        ],
    }

    try:
        session = _get_safe_session()
        response = session.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info(f"Teams notification sent for scan {scan_id}")
        return True
    except requests.exceptions.HTTPError as e:
        logger.error(f"Teams webhook returned error ({e.response.status_code}): {e}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Teams notification: {e}")
        raise


async def send_scan_notification(
    db: Session,
    scan_id: str,
    event: str,
    summary: dict,
) -> dict:
    """
    Send notifications for scan events based on user settings.

    Args:
        db: Database session
        scan_id: The scan ID
        event: Event type (e.g., "scan_complete")
        summary: Finding summary with critical, high, medium, low counts

    Returns:
        dict: Results of notification attempts
    """
    results = {
        "notifications_enabled": False,
        "slack_sent": False,
        "teams_sent": False,
        "errors": [],
    }

    try:
        # Check if notifications are enabled
        notifications_enabled = _get_setting_value(db, "notifications_enabled", False)
        if not notifications_enabled or notifications_enabled in ("false", False):
            logger.debug(f"Notifications disabled, skipping for scan {scan_id}")
            return results

        results["notifications_enabled"] = True

        # Send Slack notification if configured
        slack_url = _get_setting_value(db, "slack_webhook_url")
        if slack_url and slack_url not in ("null", "None", ""):
            try:
                results["slack_sent"] = _send_slack_notification(slack_url, summary, scan_id)
            except Exception as e:
                results["errors"].append(f"Slack: {type(e).__name__}: {e}")

        # Send Teams notification if configured
        teams_url = _get_setting_value(db, "teams_webhook_url")
        if teams_url and teams_url not in ("null", "None", ""):
            try:
                results["teams_sent"] = _send_teams_notification(teams_url, summary, scan_id)
            except Exception as e:
                results["errors"].append(f"Teams: {type(e).__name__}: {e}")

        logger.info(f"Notification results for scan {scan_id}: {results}")

    except Exception as e:
        logger.error(f"Error sending notifications for scan {scan_id}: {e}")
        results["errors"].append(str(e))

    return results
