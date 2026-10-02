"""Optional Discord and Telegram alerts for new trap hits (legacy env); configurable rules in hit_notifications."""

import logging
import os
from typing import Any

import requests

from background_tasks import submit_background
from config_store import get_config
from hit_notifications import (
    NOTIFICATION_PHASE_IMMEDIATE,
    dispatch_hit_notifications,
)

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
logger = logging.getLogger(__name__)


def _discord_notify(record: dict[str, Any]) -> None:
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        ip = record.get("ip") or "?"
        path = record.get("path") or "?"
        fp = record.get("fingerprint") or {}
        os_guess = fp.get("os_guess", "?")
        browser = fp.get("browser_guess", "?")
        ua = (fp.get("user_agent_raw") or "?")[:200]
        body = {
            "content": None,
            "embeds": [
                {
                    "title": "Honeytoken hit",
                    "description": f"**IP:** `{ip}`\n**Path:** `{path}`\n**OS:** {os_guess}\n**Browser:** {browser}\n**UA:** {ua}",
                    "color": 0xFF6600,
                }
            ],
        }
        requests.post(DISCORD_WEBHOOK_URL, json=body, timeout=10)
    except requests.RequestException as exc:
        logger.warning("Legacy Discord notification failed: %s", type(exc).__name__)


def _telegram_notify(record: dict[str, Any]) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        ip = record.get("ip") or "?"
        path = record.get("path") or "?"
        fp = record.get("fingerprint") or {}
        os_guess = fp.get("os_guess", "?")
        browser = fp.get("browser_guess", "?")
        text = f"Honeytoken hit\nIP: {ip}\nPath: {path}\nOS: {os_guess}\nBrowser: {browser}"
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except requests.RequestException as exc:
        logger.warning("Legacy Telegram notification failed: %s", type(exc).__name__)


def notify_hit(record: dict[str, Any], *, phase: str = NOTIFICATION_PHASE_IMMEDIATE) -> None:
    """Fire notifications in the background. Uses admin-configured rules when any rule is enabled; otherwise legacy env webhooks (immediate only)."""

    def _run():
        cfg = get_config()
        rules = cfg.get("notification_rules") or []
        if any(isinstance(r, dict) and r.get("enabled") for r in rules):
            dispatch_hit_notifications(record, phase, cfg)
            return
        if phase == NOTIFICATION_PHASE_IMMEDIATE:
            _discord_notify(record)
            _telegram_notify(record)

    submit_background(_run)
