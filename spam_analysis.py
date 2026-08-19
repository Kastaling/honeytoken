"""Burst/spam analysis over honeypot hits (shared by CLI and scheduled summaries)."""
from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from hit_notifications import _clean_discord_webhook_url

DEFAULT_DB = Path(__import__("os").environ.get("DATA_DIR", "/data")) / "honey.db"
MIN_BURST_HITS = 3
MIN_TIER_INTERVAL_HOURS = 1.0
MAX_TIER_INTERVAL_HOURS = 24.0 * 30
DEFAULT_DAILY_INTERVAL_HOURS = 24.0
DEFAULT_WEEKLY_INTERVAL_HOURS = 168.0
DEFAULT_BURST_WINDOW_SEC = 60
DEFAULT_TOP_IPS = 10


def fetch_hits(
    conn: sqlite3.Connection,
    start: str,
    end: str,
    *,
    hours: float = 24.0,
    start_exclusive: bool = False,
) -> list[sqlite3.Row]:
    """Load hits in a time range (naive UTC strings) or rolling hours from latest hit."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if start and end:
        start_op = ">" if start_exclusive else ">="
        cur.execute(
            f"""
            SELECT id, ip, host, path, created_at, location_display, visitor_fp_id,
                   json_extract(client_fingerprint, '$.webgl_renderer') AS webgl
            FROM hits
            WHERE created_at {start_op} ? AND created_at <= ?
            ORDER BY created_at ASC
            """,
            (start, end),
        )
    else:
        cur.execute("SELECT MAX(created_at) FROM hits")
        latest = cur.fetchone()[0]
        if not latest:
            return []
        end_dt = datetime.fromisoformat(str(latest))
        start_dt = end_dt - timedelta(hours=max(0.1, hours))
        cur.execute(
            """
            SELECT id, ip, host, path, created_at, location_display, visitor_fp_id,
                   json_extract(client_fingerprint, '$.webgl_renderer') AS webgl
            FROM hits
            WHERE created_at >= ? AND created_at <= ?
            ORDER BY created_at ASC
            """,
            (start_dt.isoformat(sep=" "), end_dt.isoformat(sep=" ")),
        )
    return cur.fetchall()


def detect_bursts(rows: Sequence[sqlite3.Row], window_sec: int) -> list[list[sqlite3.Row]]:
    if not rows:
        return []
    bursts: list[list[sqlite3.Row]] = []
    current: list[sqlite3.Row] = [rows[0]]
    prev = datetime.fromisoformat(str(rows[0]["created_at"]))
    for row in rows[1:]:
        ts = datetime.fromisoformat(str(row["created_at"]))
        if (ts - prev).total_seconds() <= window_sec:
            current.append(row)
        else:
            if len(current) >= MIN_BURST_HITS:
                bursts.append(current)
            current = [row]
        prev = ts
    if len(current) >= MIN_BURST_HITS:
        bursts.append(current)
    return bursts


def _burst_summary(burst: Sequence[sqlite3.Row], *, top_ips: int) -> dict[str, Any]:
    start = str(burst[0]["created_at"])
    end = str(burst[-1]["created_at"])
    duration = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    ips = Counter(r["ip"] for r in burst)
    hosts = Counter(r["host"] for r in burst)
    top_ip_rows: list[dict[str, Any]] = []
    for ip, count in ips.most_common(top_ips):
        loc = next(
            (r["location_display"] for r in burst if r["ip"] == ip and r["location_display"]),
            "",
        )
        top_ip_rows.append({"ip": ip, "count": count, "location": loc or ""})
    webgl = Counter((r["webgl"] or "")[:50] for r in burst if r["webgl"])
    return {
        "hit_count": len(burst),
        "duration_sec": int(duration),
        "start": start,
        "end": end,
        "hosts": [{"host": h, "count": n} for h, n in hosts.most_common()],
        "top_ips": top_ip_rows,
        "webgl_samples": [{"renderer": r, "count": n} for r, n in webgl.most_common(3)],
    }


def build_spam_report(
    rows: Sequence[sqlite3.Row],
    *,
    start: str,
    end: str,
    window_sec: int = 60,
    top_ips: int = 10,
    max_bursts: int = 8,
) -> dict[str, Any]:
    """Structured report for CLI output or Discord summaries."""
    by_min = Counter(str(r["created_at"])[:16] for r in rows)
    bursts_raw = detect_bursts(rows, window_sec)
    bursts_raw.sort(key=len, reverse=True)
    bursts = [_burst_summary(b, top_ips=top_ips) for b in bursts_raw[:max_bursts]]
    return {
        "start": start,
        "end": end,
        "hit_count": len(rows),
        "hot_minutes": [{"minute": m, "count": c} for m, c in by_min.most_common(5)],
        "burst_window_sec": window_sec,
        "burst_count": len(bursts_raw),
        "bursts_shown": len(bursts),
        "bursts": bursts,
    }


def analyze_spam_range(
    db_path: Path,
    start: str,
    end: str,
    *,
    window_sec: int = 60,
    top_ips: int = 10,
    start_exclusive: bool = False,
) -> dict[str, Any]:
    if not db_path.is_file():
        return build_spam_report([], start=start, end=end, window_sec=window_sec, top_ips=top_ips)
    conn = sqlite3.connect(str(db_path))
    try:
        rows = fetch_hits(conn, start, end, start_exclusive=start_exclusive)
    finally:
        conn.close()
    return build_spam_report(
        rows,
        start=start,
        end=end,
        window_sec=window_sec,
        top_ips=top_ips,
    )


def format_spam_report_text(report: dict[str, Any]) -> str:
    lines = [
        f"Hits in range: {report.get('hit_count', 0)}",
        f"Window: {report.get('start', '')} → {report.get('end', '')}",
    ]
    hot = report.get("hot_minutes") or []
    if hot:
        lines.append("\nBusiest minutes:")
        for item in hot:
            lines.append(f"  {item['minute']}: {item['count']} hits")
    burst_count = int(report.get("burst_count") or 0)
    window = int(report.get("burst_window_sec") or 60)
    lines.append(f"\nBursts (>={MIN_BURST_HITS} hits within {window}s gaps): {burst_count}")
    for i, burst in enumerate(report.get("bursts") or [], 1):
        lines.append(
            f"\n--- Burst #{i}: {burst['hit_count']} hits in {burst['duration_sec']}s "
            f"({burst['start']} → {burst['end']}) ---"
        )
        hosts = burst.get("hosts") or []
        if hosts:
            lines.append(
                "Hosts: "
                + ", ".join(f"{h['host']} ({h['count']})" for h in hosts[:6])
            )
        lines.append("Top IPs:")
        for row in burst.get("top_ips") or []:
            loc = f"  {row['location']}" if row.get("location") else ""
            lines.append(f"  {row['count']:4d}  {row['ip']:42s}{loc}")
        wgs = burst.get("webgl_samples") or []
        if wgs:
            lines.append(
                "WebGL samples: "
                + ", ".join(f"{w['renderer']!r} ({w['count']})" for w in wgs)
            )
    if burst_count == 0:
        lines.append("No multi-hit bursts detected in this window.")
    return "\n".join(lines)


def format_spam_report_discord_description(report: dict[str, Any], *, tier_label: str) -> str:
    """Discord embed description (max 4096 chars)."""
    hit_count = int(report.get("hit_count") or 0)
    if hit_count == 0:
        return (
            f"**{tier_label} spam summary**\n"
            f"No hits recorded between `{report.get('start', '')}` and `{report.get('end', '')}`."
        )
    lines = [
        f"**{hit_count}** hits · `{report.get('start', '')}` → `{report.get('end', '')}`",
    ]
    hot = report.get("hot_minutes") or []
    if hot:
        lines.append(
            "**Busiest minutes:** "
            + " · ".join(f"`{h['minute']}` ({h['count']})" for h in hot[:5])
        )
    burst_count = int(report.get("burst_count") or 0)
    window = int(report.get("burst_window_sec") or 60)
    lines.append(f"**Bursts** (≥{MIN_BURST_HITS} hits / {window}s): **{burst_count}**")
    for i, burst in enumerate(report.get("bursts") or [], 1):
        lines.append(
            f"\n**Burst {i}** — {burst['hit_count']} hits / {burst['duration_sec']}s "
            f"(`{burst['start']}` → `{burst['end']}`)"
        )
        hosts = burst.get("hosts") or []
        if hosts:
            lines.append(
                "Hosts: "
                + ", ".join(f"`{h['host']}`×{h['count']}" for h in hosts[:4])
            )
        for row in (burst.get("top_ips") or [])[:5]:
            loc = f" — {row['location']}" if row.get("location") else ""
            lines.append(f"• `{row['ip']}` ×{row['count']}{loc}")
        wgs = burst.get("webgl_samples") or []
        if wgs:
            lines.append(
                "WebGL: "
                + " · ".join(f"`{w['renderer'][:40]}`×{w['count']}" for w in wgs[:2])
            )
    shown = int(report.get("bursts_shown") or 0)
    if burst_count > shown:
        lines.append(f"\n_+ {burst_count - shown} more burst(s) not shown._")
    text = "\n".join(lines)
    return text[:4090] + ("…" if len(text) > 4090 else "")


def _parse_ts(raw: str) -> datetime | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _clamp_interval(hours: float, *, default: float) -> float:
    try:
        val = float(hours)
    except (TypeError, ValueError):
        val = default
    return max(MIN_TIER_INTERVAL_HOURS, min(MAX_TIER_INTERVAL_HOURS, val))


def _clamp_int(raw: Any, *, default: int, lo: int, hi: int) -> int:
    try:
        val = int(raw)
    except (TypeError, ValueError):
        val = default
    return max(lo, min(hi, val))


def normalize_spam_summary_settings(cfg: dict | None) -> dict[str, Any]:
    """Normalize spam summary config; daily and weekly tiers are fully independent."""
    cfg = cfg or {}
    out: dict[str, Any] = {}
    for tier, default_hours in (
        ("daily", DEFAULT_DAILY_INTERVAL_HOURS),
        ("weekly", DEFAULT_WEEKLY_INTERVAL_HOURS),
    ):
        enabled = bool(cfg.get(f"spam_summary_{tier}_enabled"))
        url = _clean_discord_webhook_url(cfg.get(f"spam_summary_{tier}_webhook_url") or "")
        hours = _clamp_interval(
            cfg.get(f"spam_summary_{tier}_interval_hours"),
            default=default_hours,
        )
        last_dt = _parse_ts(cfg.get(f"spam_summary_{tier}_last_sent_at") or "")
        out[f"spam_summary_{tier}_enabled"] = enabled and bool(url)
        out[f"spam_summary_{tier}_webhook_url"] = url
        out[f"spam_summary_{tier}_interval_hours"] = hours
        out[f"spam_summary_{tier}_last_sent_at"] = (
            last_dt.isoformat(sep=" ") if last_dt else ""
        )
    out["spam_summary_burst_window_sec"] = _clamp_int(
        cfg.get("spam_summary_burst_window_sec"),
        default=DEFAULT_BURST_WINDOW_SEC,
        lo=15,
        hi=600,
    )
    out["spam_summary_top_ips"] = _clamp_int(
        cfg.get("spam_summary_top_ips"),
        default=DEFAULT_TOP_IPS,
        lo=3,
        hi=25,
    )
    return out
