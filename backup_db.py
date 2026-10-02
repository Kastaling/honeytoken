#!/usr/bin/env python3
"""Create a consistent online backup of the SQLite database, including WAL data."""

from __future__ import annotations

import argparse
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/honey.db"))
    parser.add_argument("--destination-dir", type=Path, default=Path("backups"))
    args = parser.parse_args()
    if not args.source.is_file():
        parser.error(f"database does not exist: {args.source}")
    args.destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = args.destination_dir / f"honey-{stamp}.db"
    with sqlite3.connect(f"file:{args.source.resolve()}?mode=ro", uri=True) as source:
        with sqlite3.connect(destination) as target:
            source.backup(target)
            result = target.execute("PRAGMA quick_check").fetchone()
    if not result or result[0] != "ok":
        destination.unlink(missing_ok=True)
        raise SystemExit("backup integrity check failed")
    print(destination)


if __name__ == "__main__":
    main()
