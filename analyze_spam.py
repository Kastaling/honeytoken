#!/usr/bin/env python3
"""Summarize burst/spam patterns in honeypot hit logs.

Usage (inside container or with DATA_DIR/honey.db available):
  python analyze_spam.py
  python analyze_spam.py --hours 6 --window 60
  python analyze_spam.py --start '2026-08-17 23:39:00' --end '2026-08-18 00:52:00'

Docker:
  docker exec honey python3 analyze_spam.py --hours 24
"""

from __future__ import annotations

import argparse
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from spam_analysis import (
    DEFAULT_DB,
    build_spam_report,
    fetch_hits,
    format_spam_report_text,
)

MIN_BURST_HITS = 3  # re-export for CLI messaging


def _parse_timestamp_arg(raw: str, label: str) -> str:
    """Parse --start/--end into the DB timestamp format (naive UTC string)."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"Invalid --{label} timestamp {raw!r}; use ISO format like YYYY-MM-DD HH:MM:SS") from exc
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.isoformat(sep=" ")


def _validate_time_range(args: argparse.Namespace) -> tuple[str, str]:
    start = _parse_timestamp_arg(args.start, "start")
    end = _parse_timestamp_arg(args.end, "end")
    if bool(start) != bool(end):
        raise SystemExit("--start and --end must both be set or both omitted")
    if start and end and start > end:
        raise SystemExit("--start must be before or equal to --end")
    return start, end


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze honeypot hit bursts")
    p.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to honey.db")
    p.add_argument("--hours", type=float, default=24.0, help="Look back N hours from latest hit")
    p.add_argument("--start", type=str, default="", help="UTC start timestamp (YYYY-MM-DD HH:MM:SS)")
    p.add_argument("--end", type=str, default="", help="UTC end timestamp")
    p.add_argument("--window", type=int, default=60, help="Burst window seconds (hits grouped if within this gap)")
    p.add_argument("--top", type=int, default=10, help="Top N IPs to show per burst")
    args = p.parse_args()
    args.start, args.end = _validate_time_range(args)
    return args


def main() -> None:
    args = _parse_args()
    if not args.db.is_file():
        raise SystemExit(f"Database not found: {args.db}")

    conn = sqlite3.connect(str(args.db))
    rows = fetch_hits(conn, args.start, args.end, hours=args.hours)
    conn.close()

    if args.start and args.end:
        start, end = args.start, args.end
    elif rows:
        start = str(rows[0]["created_at"])
        end = str(rows[-1]["created_at"])
    else:
        start, end = "", ""

    report = build_spam_report(
        rows,
        start=start,
        end=end,
        window_sec=args.window,
        top_ips=args.top,
    )
    print(format_spam_report_text(report))


if __name__ == "__main__":
    main()
