"""Scheduled Discord spam/burst summaries (daily and weekly tiers, independent cursors)."""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import requests

from config_store import get_config, save_config
from hit_notifications import _clean_discord_webhook_url
from spam_analysis import (
    DEFAULT_DB,
    analyze_spam_range,
    format_spam_report_discord_description,
    normalize_spam_summary_settings,
)

_log = logging.getLogger(__name__)

POLL_INTERVAL_SEC = int(os.environ.get("SPAM_SUMMARY_POLL_SEC", "60"))

_TIERS = ("daily", "weekly")
_LOCK = threading.Lock()


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _parse_ts(raw: str) -> datetime | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _tier_config(cfg: dict, tier: str) -> dict[str, Any]:
    norm = normalize_spam_summary_settings(cfg)
    return {
        "enabled": norm[f"spam_summary_{tier}_enabled"],
        "webhook_url": norm[f"spam_summary_{tier}_webhook_url"],
        "interval_hours": norm[f"spam_summary_{tier}_interval_hours"],
        "last_sent_at": norm[f"spam_summary_{tier}_last_sent_at"],
        "burst_window_sec": norm["spam_summary_burst_window_sec"],
        "top_ips": norm["spam_summary_top_ips"],
    }


def _tier_due(tier_cfg: dict[str, Any], now: datetime) -> bool:
    if not tier_cfg["enabled"] or not tier_cfg["webhook_url"]:
        return False
    last = _parse_ts(tier_cfg["last_sent_at"])
    if last is None:
        return True
    return now >= last + timedelta(hours=tier_cfg["interval_hours"])


def _tier_range(tier_cfg: dict[str, Any], now: datetime) -> tuple[str, str]:
    """Exclusive start cursor, inclusive end — tiers never share cursors."""
    last = _parse_ts(tier_cfg["last_sent_at"])
    if last is None:
        start_dt = now - timedelta(hours=tier_cfg["interval_hours"])
    else:
        start_dt = last
    end_dt = now
    if start_dt >= end_dt:
        start_dt = end_dt - timedelta(minutes=1)
    return start_dt.isoformat(sep=" "), end_dt.isoformat(sep=" ")


def _tier_title(tier: str) -> str:
    return "Daily spam summary" if tier == "daily" else "Weekly spam summary"


def _tier_color(tier: str) -> int:
    return 0x5865F2 if tier == "daily" else 0x9B59B6


def send_spam_summary_discord(
    webhook_url: str,
    *,
    tier: str,
    report: dict[str, Any],
) -> bool:
    url = _clean_discord_webhook_url(webhook_url)
    if not url:
        return False
    tier_label = _tier_title(tier)
    embed = {
        "title": tier_label,
        "description": format_spam_report_discord_description(report, tier_label=tier_label),
        "color": _tier_color(tier),
    }
    payload = {"embeds": [embed], "username": "Honeytoken"}
    try:
        resp = requests.post(url, json=payload, timeout=20)
        return 200 <= resp.status_code < 300
    except requests.RequestException:
        return False


def run_spam_summary_tier(tier: str, *, now: datetime | None = None) -> bool:
    """Run one tier if due. Returns True when a summary was sent."""
    if tier not in _TIERS:
        return False
    now = now or _utc_now()
    with _LOCK:
        cfg = get_config()
        tier_cfg = _tier_config(cfg, tier)
        if not _tier_due(tier_cfg, now):
            return False
        start, end = _tier_range(tier_cfg, now)
        report = analyze_spam_range(
            DEFAULT_DB,
            start,
            end,
            window_sec=tier_cfg["burst_window_sec"],
            top_ips=tier_cfg["top_ips"],
            start_exclusive=bool(tier_cfg["last_sent_at"]),
        )
        ok = send_spam_summary_discord(
            tier_cfg["webhook_url"],
            tier=tier,
            report=report,
        )
        if not ok:
            _log.warning("spam summary %s Discord webhook failed", tier)
            return False
        save_config({f"spam_summary_{tier}_last_sent_at": end})
        _log.info(
            "spam summary %s sent (%s hits, %s → %s)",
            tier,
            report.get("hit_count", 0),
            start,
            end,
        )
        return True


def run_due_spam_summaries(*, now: datetime | None = None) -> None:
    now = now or _utc_now()
    for tier in _TIERS:
        try:
            run_spam_summary_tier(tier, now=now)
        except Exception:
            _log.exception("spam summary tier %s failed", tier)


def _scheduler_loop() -> None:
    while True:
        try:
            run_due_spam_summaries()
        except Exception:
            _log.exception("spam summary scheduler tick failed")
        time.sleep(max(15, POLL_INTERVAL_SEC))


def start_spam_summary_scheduler() -> threading.Thread | None:
    if os.environ.get("SPAM_SUMMARY_SCHEDULER", "1").strip().lower() in ("0", "false", "no", "off"):
        return None
    thread = threading.Thread(
        target=_scheduler_loop,
        name="spam-summary-scheduler",
        daemon=True,
    )
    thread.start()
    return thread
