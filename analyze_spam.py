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
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_DB = Path(__import__("os").environ.get("DATA_DIR", "/data")) / "honey.db"
MIN_BURST_HITS = 3


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze honeypot hit bursts")
    p.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to honey.db")
    p.add_argument("--hours", type=float, default=24.0, help="Look back N hours from latest hit")
    p.add_argument("--start", type=str, default="", help="UTC start timestamp (YYYY-MM-DD HH:MM:SS)")
    p.add_argument("--end", type=str, default="", help="UTC end timestamp")
    p.add_argument("--window", type=int, default=60, help="Burst window seconds (hits grouped if within this gap)")
    p.add_argument("--top", type=int, default=10, help="Top N IPs to show per burst")
    return p.parse_args()


def _fetch_hits(conn: sqlite3.Connection, start: str, end: str, *, hours: float = 24.0) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if start and end:
        cur.execute(
            """
            SELECT id, ip, host, path, created_at, location_display, visitor_fp_id,
                   json_extract(client_fingerprint, '$.webgl_renderer') AS webgl
            FROM hits
            WHERE created_at >= ? AND created_at <= ?
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


def _detect_bursts(rows: list[sqlite3.Row], window_sec: int) -> list[list[sqlite3.Row]]:
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


def _print_burst(idx: int, burst: list[sqlite3.Row], top: int) -> None:
    start = burst[0]["created_at"]
    end = burst[-1]["created_at"]
    duration = (datetime.fromisoformat(str(end)) - datetime.fromisoformat(str(start))).total_seconds()
    ips = Counter(r["ip"] for r in burst)
    hosts = Counter(r["host"] for r in burst)
    print(f"\n--- Burst #{idx}: {len(burst)} hits in {duration:.0f}s ({start} → {end}) ---")
    print("Hosts:", ", ".join(f"{h} ({n})" for h, n in hosts.most_common()))
    print("Top IPs:")
    for ip, n in ips.most_common(top):
        loc = next((r["location_display"] for r in burst if r["ip"] == ip and r["location_display"]), "")
        print(f"  {n:4d}  {ip:42s}  {loc}")
    wgs = Counter((r["webgl"] or "")[:50] for r in burst if r["webgl"])
    if wgs:
        print("WebGL samples:", wgs.most_common(3))


def main() -> None:
    args = _parse_args()
    if not args.db.is_file():
        raise SystemExit(f"Database not found: {args.db}")

    conn = sqlite3.connect(str(args.db))
    rows = _fetch_hits(conn, args.start.strip(), args.end.strip(), hours=args.hours)
    conn.close()

    print(f"Hits in range: {len(rows)}")
    if not rows:
        return

    by_min = Counter(str(r["created_at"])[:16] for r in rows)
    hot_minutes = by_min.most_common(5)
    if hot_minutes:
        print("\nBusiest minutes:")
        for minute, count in hot_minutes:
            print(f"  {minute}: {count} hits")

    bursts = _detect_bursts(rows, args.window)
    print(f"\nBursts (>={MIN_BURST_HITS} hits within {args.window}s gaps): {len(bursts)}")
    for i, burst in enumerate(bursts, 1):
        _print_burst(i, burst, args.top)

    if not bursts:
        print("No multi-hit bursts detected in this window.")


if __name__ == "__main__":
    main()
