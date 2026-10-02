"""Periodic bounded maintenance for retained hit data."""

from __future__ import annotations

import logging
import os
import threading

from store import prune_hits_older_than

logger = logging.getLogger(__name__)
_DAY_SECONDS = 24 * 60 * 60


def _retention_days() -> int:
    try:
        return max(0, min(3650, int(os.environ.get("HIT_RETENTION_DAYS", "0"))))
    except ValueError:
        logger.warning("Invalid HIT_RETENTION_DAYS; retention is disabled")
        return 0


def _maintenance_loop(days: int) -> None:
    while True:
        try:
            deleted = prune_hits_older_than(days)
            if deleted:
                logger.info("Retention removed %s hits older than %s days", deleted, days)
        except Exception:
            logger.exception("Scheduled retention failed")
        threading.Event().wait(_DAY_SECONDS)


def start_maintenance_scheduler() -> threading.Thread | None:
    """Start daily retention when configured; zero days means keep data indefinitely."""
    days = _retention_days()
    if not days:
        return None
    thread = threading.Thread(
        target=_maintenance_loop,
        args=(days,),
        daemon=True,
        name="honey-maintenance",
    )
    thread.start()
    return thread
