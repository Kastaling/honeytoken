"""
Debounce/batch hit notifications during bursts so Discord is not spammed.

First hit in a quiet period sends immediately. Additional matching hits within the
batch window are held; when the window closes (no new hits for batch_window_sec),
one summary webhook is sent for the overflow batch.

Process model: batch state lives in module-level globals protected by a lock.
This is correct for the default single-process Waitress deployment (one worker
thread pool). Do not run under multi-worker servers (e.g. gunicorn with workers > 1)
without replacing this with shared storage — each worker would maintain separate
batch state and debouncing would not work as intended.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Callable
from typing import Any

DEFAULT_BATCH_WINDOW_SEC = 30
MIN_BATCH_WINDOW_SEC = 5
MAX_BATCH_WINDOW_SEC = 300
MAX_BATCH_OVERFLOW = 100  # max overflow hits kept for one batch summary (anchor is separate)

SendFn = Callable[[dict[str, Any], dict[str, Any], str], None]
BatchSendFn = Callable[[list[dict[str, Any]], dict[str, Any], str], None]

_LOCK = threading.Lock()
_BATCHES: dict[str, _BatchState] = {}


class _BatchState:
    __slots__ = ("hits", "timer", "phase", "rule", "overflow_dropped")

    def __init__(self, rule: dict[str, Any], phase: str) -> None:
        self.rule = rule
        self.phase = phase
        self.hits: list[dict[str, Any]] = []
        self.timer: threading.Timer | None = None
        self.overflow_dropped = 0


def normalize_batch_settings(cfg: dict[str, Any] | None) -> dict[str, Any]:
    cfg = cfg or {}
    enabled_raw = cfg.get("notification_batch_enabled")
    if enabled_raw is None:
        env_flag = (__import__("os").environ.get("NOTIFICATION_BATCH_ENABLED") or "1").strip().lower()
        enabled = env_flag not in ("0", "false", "no", "off")
    else:
        enabled = bool(enabled_raw)
    try:
        window = int(
            cfg.get("notification_batch_window_sec")
            or __import__("os").environ.get("NOTIFICATION_BATCH_WINDOW_SEC")
            or DEFAULT_BATCH_WINDOW_SEC
        )
    except (TypeError, ValueError):
        window = DEFAULT_BATCH_WINDOW_SEC
    window = max(MIN_BATCH_WINDOW_SEC, min(MAX_BATCH_WINDOW_SEC, window))
    return {"enabled": enabled, "window_sec": window}


def _batch_key(rule: dict[str, Any], phase: str) -> str:
    rid = str(rule.get("id") or "rule")
    return f"{rid}:{phase}"


def _cancel_timer(state: _BatchState) -> None:
    if state.timer is not None:
        state.timer.cancel()
        state.timer = None


def _flush_batch(
    key: str,
    *,
    send_one: SendFn,
    send_batch: BatchSendFn,
) -> None:
    with _LOCK:
        state = _BATCHES.pop(key, None)
    if not state or len(state.hits) <= 1:
        return
    overflow = state.hits[1:]
    rule = dict(state.rule)
    if state.overflow_dropped:
        rule["_batch_overflow_dropped"] = state.overflow_dropped
    phase = state.phase
    send_batch(overflow, rule, phase)


def _schedule_flush(
    key: str,
    window_sec: int,
    *,
    send_one: SendFn,
    send_batch: BatchSendFn,
) -> None:
    def _on_fire() -> None:
        _flush_batch(key, send_one=send_one, send_batch=send_batch)

    with _LOCK:
        state = _BATCHES.get(key)
        if not state:
            return
        _cancel_timer(state)
        state.timer = threading.Timer(window_sec, _on_fire)
        state.timer.daemon = True
        state.timer.start()


def enqueue_notification(
    hit: dict[str, Any],
    rule: dict[str, Any],
    phase: str,
    cfg: dict[str, Any],
    *,
    send_one: SendFn,
    send_batch: BatchSendFn,
    force_immediate: bool = False,
) -> None:
    """Queue a hit notification; may send immediately, batched, or deferred."""
    if force_immediate or hit.get("_notification_test"):
        send_one(hit, rule, phase)
        return

    batch_cfg = normalize_batch_settings(cfg)
    if not batch_cfg["enabled"]:
        send_one(hit, rule, phase)
        return

    key = _batch_key(rule, phase)
    window_sec = batch_cfg["window_sec"]

    with _LOCK:
        state = _BATCHES.get(key)
        if state is None:
            state = _BatchState(rule, phase)
            _BATCHES[key] = state
            state.hits = [hit]
            immediate = True
        else:
            state.hits.append(hit)
            overflow = state.hits[1:]
            if len(overflow) > MAX_BATCH_OVERFLOW:
                state.overflow_dropped += len(overflow) - MAX_BATCH_OVERFLOW
                overflow = overflow[-MAX_BATCH_OVERFLOW:]
                state.hits = [state.hits[0]] + overflow
            immediate = False

    if immediate:
        send_one(hit, rule, phase)
        _schedule_flush(key, window_sec, send_one=send_one, send_batch=send_batch)
    else:
        _schedule_flush(key, window_sec, send_one=send_one, send_batch=send_batch)


def build_batch_summary_lines(hits: list[dict[str, Any]], phase: str, *, dropped: int = 0) -> list[str]:
    """Markdown lines for a batched Discord embed description."""
    count = len(hits)
    hosts = Counter((h.get("host") or "?").strip() for h in hits)
    ips = Counter((h.get("ip") or "?").strip() for h in hits)
    paths = Counter((h.get("path") or "/").strip() for h in hits)

    gpu_count = 0
    for h in hits:
        cf = h.get("client_fingerprint") if isinstance(h.get("client_fingerprint"), dict) else {}
        if str(cf.get("webgl_renderer") or "").strip():
            gpu_count += 1

    lines = [
        f"**{count} additional hits** batched after the first alert *(phase: `{phase}`)*.",
        "",
        "**Hosts:**",
    ]
    for host, n in hosts.most_common(5):
        lines.append(f"- `{host}` — {n}")
    lines.extend(["", "**Top IPs:**"])
    for ip, n in ips.most_common(8):
        loc = next((h.get("location_display") for h in hits if h.get("ip") == ip and h.get("location_display")), "")
        suffix = f" ({loc})" if loc else ""
        lines.append(f"- `{ip}` — {n}{suffix}")
    if len(paths) <= 3:
        lines.extend(["", "**Paths:** " + ", ".join(f"`{p}` ({n})" for p, n in paths.most_common(3))])
    if phase == "after_capture" and gpu_count:
        lines.append(f"\n**GPU captured:** {gpu_count}/{count}")
    if dropped:
        lines.append(f"\n*({dropped} older batched hits omitted from this summary)*")
    lines.append("\n*Individual hits are in the admin dashboard.*")
    return lines
