"""Bounded background work shared by notifications and other non-request tasks."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

logger = logging.getLogger(__name__)

_MAX_WORKERS = max(1, min(32, int(os.environ.get("BACKGROUND_WORKERS", "4"))))
_QUEUE_CAPACITY = max(
    _MAX_WORKERS,
    min(1000, int(os.environ.get("BACKGROUND_QUEUE_CAPACITY", "128"))),
)
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="honey-bg")
_SLOTS = threading.BoundedSemaphore(_QUEUE_CAPACITY)
_METRICS_LOCK = threading.Lock()
_PENDING = 0
_DROPPED = 0


def _log_result(future: Future[Any], task_name: str) -> None:
    global _PENDING
    _SLOTS.release()
    with _METRICS_LOCK:
        _PENDING -= 1
    try:
        future.result()
    except Exception:
        logger.exception("Background task failed: %s", task_name)


def submit_background(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> bool:
    """Submit work without allowing an unbounded queue; return False when saturated."""
    global _DROPPED, _PENDING
    if not _SLOTS.acquire(blocking=False):
        with _METRICS_LOCK:
            _DROPPED += 1
        logger.warning("Background task queue full; dropped task: %s", fn.__name__)
        return False
    try:
        future = _EXECUTOR.submit(fn, *args, **kwargs)
    except Exception:
        _SLOTS.release()
        logger.exception("Unable to submit background task: %s", fn.__name__)
        return False
    with _METRICS_LOCK:
        _PENDING += 1
    future.add_done_callback(lambda completed: _log_result(completed, fn.__name__))
    return True


def background_status() -> dict[str, int]:
    with _METRICS_LOCK:
        return {
            "workers": _MAX_WORKERS,
            "capacity": _QUEUE_CAPACITY,
            "pending": _PENDING,
            "dropped": _DROPPED,
        }
