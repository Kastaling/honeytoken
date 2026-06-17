"""Persistent config for trap final action: redirect URL or status code."""
import json
import os
import random
import re
import secrets
import threading
from pathlib import Path
from urllib.parse import urlparse

from hit_notifications import normalize_notification_rules

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_FILE = DATA_DIR / "config.json"
_LOCK = threading.Lock()

DEFAULT_TIMEZONE = "UTC"

DEFAULTS = {
    "default_redirect_url": "",
    "status_code": 404,
    "media_url": "",
    "media_type": "",  # image | gif | video | youtube
    "media_tab_mode": "none",  # none | static | scrolling | rotating
    "media_tab_static_text": "",
    "media_tab_scrolling_text": "",
    "media_tab_rotating_messages": "",  # newline-separated
    "media_tab_rotate_interval_sec": 3,
    "host_settings": {},  # host -> { mode, ... media_tab_* ... }
    "timezone": DEFAULT_TIMEZONE,  # dashboard display timezone (IANA name)
    "notification_rules": [],  # hit_notifications.normalize_notification_rules
}
VALID_MEDIA_TYPES = ("image", "gif", "video", "youtube")
VALID_MODES = ("redirect", "media", "error")
VALID_MEDIA_TAB_MODES = ("none", "static", "scrolling", "rotating")
MEDIA_TAB_MESSAGE_MAX_LEN = 500
MEDIA_TAB_ROTATE_MAX_MESSAGES = 20
MEDIA_TAB_ROTATE_INTERVAL_MIN = 1
MEDIA_TAB_ROTATE_INTERVAL_MAX = 60
ACTION_URL_MAX_LEN = 2048
MAX_FINAL_ACTIONS = 20
ACTION_LABEL_MAX_LEN = 80
_ACTION_ID_RE = re.compile(r"^[a-f0-9]{8,32}$")
VALID_STATUS_CODES = (
    403, 404, 410, 412, 418,
    500, 501, 502, 503, 504, 505, 506, 507, 508,
)


def _clean_url(raw: str, *, allow_local_media: bool = False) -> str:
    """Return a bounded http(s) URL, or a local /media path when explicitly allowed."""
    url = (raw or "").strip()[:ACTION_URL_MAX_LEN]
    if not url:
        return ""
    lowered = url.lower()
    if lowered.startswith(("javascript:", "data:", "vbscript:", "//")):
        return ""
    if allow_local_media and url.startswith("/media/"):
        return url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return ""
    return url


def _normalize_action_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-f0-9]", "", (raw or "").strip().lower())[:32]
    if _ACTION_ID_RE.match(cleaned):
        return cleaned
    return secrets.token_hex(8)


def normalize_single_action(opts: dict | None) -> dict:
    """Normalize one redirect/media/error action (no random-actions metadata)."""
    if not isinstance(opts, dict):
        opts = {}
    mode = (opts.get("mode") or "").strip().lower()
    if mode not in VALID_MODES:
        if (opts.get("default_redirect_url") or "").strip():
            mode = "redirect"
        elif (opts.get("media_url") or "").strip() and (opts.get("media_type") or "").strip():
            mode = "media"
        else:
            mode = "error"
    url = _clean_url(opts.get("default_redirect_url") or "")
    media_url = _clean_url(opts.get("media_url") or "", allow_local_media=True)
    media_type = (opts.get("media_type") or "").strip().lower()
    if media_type not in VALID_MEDIA_TYPES:
        media_type = ""
    try:
        code = int(opts.get("status_code", 404))
    except (ValueError, TypeError):
        code = 404
    if code not in VALID_STATUS_CODES:
        code = 404
    tab_mode = (opts.get("media_tab_mode") or "none").strip().lower()
    if tab_mode not in VALID_MEDIA_TAB_MODES:
        tab_mode = "none"
    tab_static = (opts.get("media_tab_static_text") or "")[:MEDIA_TAB_MESSAGE_MAX_LEN]
    tab_scrolling = (opts.get("media_tab_scrolling_text") or "")[:MEDIA_TAB_MESSAGE_MAX_LEN]
    tab_rotating_raw = (opts.get("media_tab_rotating_messages") or "").strip()
    tab_rotating = "\n".join(
        line.strip()[:MEDIA_TAB_MESSAGE_MAX_LEN]
        for line in tab_rotating_raw.split("\n")[:MEDIA_TAB_ROTATE_MAX_MESSAGES]
        if line.strip()
    )
    try:
        tab_interval = int(opts.get("media_tab_rotate_interval_sec", 3))
    except (ValueError, TypeError):
        tab_interval = 3
    tab_interval = max(MEDIA_TAB_ROTATE_INTERVAL_MIN, min(MEDIA_TAB_ROTATE_INTERVAL_MAX, tab_interval))
    return {
        "mode": mode,
        "default_redirect_url": url if mode == "redirect" else "",
        "media_url": media_url if mode == "media" else "",
        "media_type": media_type if mode == "media" else "",
        "media_tab_mode": tab_mode if mode == "media" else "none",
        "media_tab_static_text": tab_static if mode == "media" else "",
        "media_tab_scrolling_text": tab_scrolling if mode == "media" else "",
        "media_tab_rotating_messages": tab_rotating if mode == "media" else "",
        "media_tab_rotate_interval_sec": tab_interval if mode == "media" else 3,
        "status_code": code,
    }


def normalize_action_item(item: dict | None) -> dict | None:
    """Normalize one entry in the randomized final-actions list."""
    if not isinstance(item, dict):
        return None
    single = normalize_single_action(item)
    return {
        "id": _normalize_action_id(str(item.get("id") or "")),
        "label": (item.get("label") or "").strip()[:ACTION_LABEL_MAX_LEN],
        **single,
    }


def normalize_action_settings(opts: dict | None) -> dict:
    """Normalize settings including optional randomized final-action pool."""
    if not isinstance(opts, dict):
        opts = {}
    single = normalize_single_action(opts)
    random_enabled = bool(opts.get("random_actions_enabled"))
    actions: list[dict] = []
    seen_ids: set[str] = set()
    raw_actions = opts.get("actions")
    if isinstance(raw_actions, list):
        for raw in raw_actions[:MAX_FINAL_ACTIONS]:
            norm = normalize_action_item(raw)
            if not norm or norm["id"] in seen_ids:
                continue
            seen_ids.add(norm["id"])
            actions.append(norm)
    return {
        **single,
        "random_actions_enabled": random_enabled,
        "actions": actions,
    }


def resolve_action_for_capture(opts: dict | None) -> dict:
    """Return one concrete action dict for /capture (random pick when enabled)."""
    normalized = normalize_action_settings(opts)
    pool = normalized.get("actions") or []
    if normalized.get("random_actions_enabled") and pool:
        return normalize_single_action(random.choice(pool))
    return normalize_single_action(normalized)


def _action_signature(action: dict) -> tuple:
    """Comparable key for matching a resolved action to a pool entry."""
    n = normalize_single_action(action)
    return (
        n.get("mode"),
        n.get("default_redirect_url"),
        n.get("media_url"),
        n.get("media_type"),
        n.get("status_code"),
    )


def _media_basename(media_url: str) -> str:
    """Filename from /media/foo.mp4 or the last path segment of a URL."""
    url = (media_url or "").strip()
    if not url:
        return ""
    if url.startswith("/media/"):
        name = url.split("/media/", 1)[-1]
        return name.split("?")[0].split("#")[0].strip("/").split("/")[-1][:255]
    parsed = urlparse(url)
    segment = (parsed.path or "").rstrip("/").rsplit("/", 1)[-1]
    return (segment or url)[:255]


def describe_final_action_taken(settings: dict | None, resolved: dict | None) -> dict:
    """Build a safe summary of the final action served to the visitor (for webhooks)."""
    norm_settings = normalize_action_settings(settings)
    norm_resolved = normalize_single_action(resolved)
    random_used = bool(norm_settings.get("random_actions_enabled") and norm_settings.get("actions"))
    pool_size = len(norm_settings.get("actions") or []) if random_used else 0
    label = ""
    if random_used:
        sig = _action_signature(norm_resolved)
        for item in norm_settings.get("actions") or []:
            if _action_signature(item) == sig:
                label = (item.get("label") or "").strip()[:ACTION_LABEL_MAX_LEN]
                break
    mode = norm_resolved.get("mode") or "error"
    media_url = norm_resolved.get("media_url") or ""
    media_type = norm_resolved.get("media_type") or ""
    media_filename = _media_basename(media_url) if mode == "media" else ""
    if mode == "redirect":
        detail = (norm_resolved.get("default_redirect_url") or "")[:ACTION_URL_MAX_LEN]
    elif mode == "media":
        detail = media_filename or media_url[:ACTION_URL_MAX_LEN]
    else:
        detail = str(norm_resolved.get("status_code", 404))
    return {
        "mode": mode,
        "random": random_used,
        "pool_size": pool_size,
        "label": label,
        "detail": detail,
        "media_type": media_type,
        "media_filename": media_filename,
    }


def _normalize_host_settings(host_settings: dict) -> dict:
    """Ensure host_settings is a dict of dicts with valid keys."""
    if not isinstance(host_settings, dict):
        return {}
    out = {}
    for host, opts in host_settings.items():
        if not isinstance(host, str) or not host.strip():
            continue
        out[host.strip().lower()[:255]] = normalize_action_settings(opts)
    return out


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_config() -> dict:
    _LOCK.acquire()
    try:
        _ensure_data_dir()
        if not CONFIG_FILE.exists():
            return dict(DEFAULTS)
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        out = dict(DEFAULTS)
        out.update(data)
        out.update(normalize_action_settings(out))
        if "host_settings" in out and isinstance(out["host_settings"], dict):
            out["host_settings"] = _normalize_host_settings(out["host_settings"])
        else:
            out["host_settings"] = {}
        if isinstance(out.get("notification_rules"), list):
            out["notification_rules"] = normalize_notification_rules(out["notification_rules"])
        else:
            out["notification_rules"] = []
        return out
    finally:
        _LOCK.release()


def save_config(updates: dict) -> dict:
    _LOCK.acquire()
    try:
        _ensure_data_dir()
        if CONFIG_FILE.exists():
            current = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        else:
            current = dict(DEFAULTS)
        if "host_settings" in updates:
            current["host_settings"] = _normalize_host_settings(updates["host_settings"])
            updates = {k: v for k, v in updates.items() if k != "host_settings"}
        if "notification_rules" in updates:
            current["notification_rules"] = normalize_notification_rules(updates["notification_rules"])
            updates = {k: v for k, v in updates.items() if k != "notification_rules"}
        current.update(updates)
        current.update(normalize_action_settings(current))
        if "host_settings" in current and not isinstance(current["host_settings"], dict):
            current["host_settings"] = {}
        else:
            current["host_settings"] = _normalize_host_settings(current.get("host_settings", {}))
        if isinstance(current.get("notification_rules"), list):
            current["notification_rules"] = normalize_notification_rules(current["notification_rules"])
        else:
            current["notification_rules"] = []
        CONFIG_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
        return dict(DEFAULTS) | current
    finally:
        _LOCK.release()
