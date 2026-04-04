#!/usr/bin/env python3
"""Send notifications to Slack or other channels"""

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


def _validate_webhook_url(url: str) -> bool:
    """Validate webhook URL is not targeting internal networks."""
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            logger.warning(f"Webhook URL rejected: scheme must be https, got {parsed.scheme}")
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, addr in resolved:
            ip = ipaddress.ip_address(addr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                logger.warning(f"Webhook URL rejected: resolves to private/internal IP {addr[0]}")
                return False
        return True
    except Exception as e:
        logger.warning(f"Webhook URL validation failed: {e}")
        return False


def send_slack_notification(webhook_url, summary):
    """Send audit summary to Slack"""
    if not _validate_webhook_url(webhook_url):
        return False

    message = {
        "text": "🔒 Cloud Security Audit Complete",
        "attachments": [
            {
                "color": "danger" if summary.get("critical", 0) > 0 else (
                    "warning" if summary.get("high", 0) > 0 else "good"
                ),
                "fields": [
                    {
                        "title": "Critical",
                        "value": summary.get("critical", 0),
                        "short": True,
                    },
                    {"title": "High", "value": summary.get("high", 0), "short": True},
                    {
                        "title": "Medium",
                        "value": summary.get("medium", 0),
                        "short": True,
                    },
                    {"title": "Low", "value": summary.get("low", 0), "short": True},
                ],
            }
        ],
    }

    try:
        response = requests.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info("Slack notification sent successfully")
        return True
    except requests.exceptions.HTTPError as e:
        logger.error(f"Slack webhook returned error ({e.response.status_code}): {e}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Slack notification (network error): {e}")
        return False


def send_teams_notification(webhook_url: str, summary: dict, scan_id: str = None) -> bool:
    """
    Send audit summary to Microsoft Teams via webhook.

    Args:
        webhook_url: Microsoft Teams incoming webhook URL
        summary: Dictionary with critical, high, medium, low counts
        scan_id: Optional scan ID for linking

    Returns:
        True if notification sent successfully, False otherwise
    """
    if not _validate_webhook_url(webhook_url):
        return False

    # Calculate total
    total = sum([
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
    ])

    # Determine card color based on severity
    if summary.get("critical", 0) > 0:
        theme_color = "FF0000"  # Red
    elif summary.get("high", 0) > 0:
        theme_color = "FFA500"  # Orange
    elif summary.get("medium", 0) > 0:
        theme_color = "FFFF00"  # Yellow
    else:
        theme_color = "00FF00"  # Green

    # Microsoft Teams Adaptive Card (Message Card format for webhook)
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
        response = requests.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info("Teams notification sent successfully")
        return True
    except requests.exceptions.Timeout:
        logger.error("Teams notification timed out")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Teams notification: {e}")
        return False


def send_notification(
    channel: str,
    webhook_url: str,
    summary: dict,
    scan_id: str = None,
) -> bool:
    """
    Unified notification dispatcher.

    Args:
        channel: Notification channel ("slack" or "teams")
        webhook_url: Webhook URL for the channel
        summary: Dictionary with finding counts
        scan_id: Optional scan ID

    Returns:
        True if notification sent successfully, False otherwise
    """
    if not webhook_url or webhook_url in ("null", "None", ""):
        logger.debug(f"No webhook URL configured for {channel}")
        return False

    channel_lower = channel.lower()

    if channel_lower == "slack":
        return send_slack_notification(webhook_url, summary)

    elif channel_lower == "teams":
        return send_teams_notification(webhook_url, summary, scan_id)

    else:
        logger.warning(f"Unknown notification channel: {channel}")
        return False


if __name__ == "__main__":
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook_url:
        # Load summary from database or file
        summary = {"critical": 5, "high": 12, "medium": 34, "low": 89}
        send_slack_notification(webhook_url, summary)

    # Test Teams notification
    teams_url = os.environ.get("TEAMS_WEBHOOK_URL")
    if teams_url:
        summary = {"critical": 5, "high": 12, "medium": 34, "low": 89}
        send_teams_notification(teams_url, summary, "test-scan-123")
