"""Browser visitor fingerprint: normalize client signals, stable ID, visit stats."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

VISITOR_FP_ID_LEN = 64
VISITOR_FP_SHORT_LEN = 12
MAX_CLIENT_PAYLOAD_BYTES = 32_768
MAX_STRING_FIELD = 512
MAX_LANGUAGES = 12
MAX_FONT_LIST = 64
_HEX_RE = re.compile(r"^[a-f0-9]{1,128}$")


def _clip_str(val: Any, limit: int = MAX_STRING_FIELD) -> str:
    if val is None:
        return ""
    return str(val).strip()[:limit]


def _clip_int(val: Any, lo: int, hi: int) -> int | None:
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    if n < lo or n > hi:
        return None
    return n


def _clip_float(val: Any, lo: float, hi: float) -> float | None:
    try:
        n = float(val)
    except (TypeError, ValueError):
        return None
    if n < lo or n > hi:
        return None
    return round(n, 4)


def _normalize_hex_hash(val: Any, max_len: int = 128) -> str:
    s = _clip_str(val, max_len).lower()
    if not s:
        return ""
    if _HEX_RE.match(s):
        return s
    # Legacy weak 32-bit canvas hashes from trap page
    if re.fullmatch(r"[a-f0-9]{4,32}", s):
        return s
    return ""


def _normalize_languages(raw: Any) -> list[str]:
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str) and raw.strip():
        items = [raw.strip()]
    else:
        items = []
    out: list[str] = []
    for item in items[:MAX_LANGUAGES]:
        lang = _clip_str(item, 32)
        if lang and lang not in out:
            out.append(lang)
    return out


def _normalize_screen(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    w = _clip_int(raw.get("width"), 0, 16_384)
    h = _clip_int(raw.get("height"), 0, 16_384)
    cd = _clip_int(raw.get("colorDepth"), 1, 64)
    pr = _clip_float(raw.get("pixelRatio"), 0.25, 8.0)
    out: dict[str, Any] = {}
    if w is not None:
        out["width"] = w
    if h is not None:
        out["height"] = h
    if cd is not None:
        out["colorDepth"] = cd
    if pr is not None:
        out["pixelRatio"] = pr
    return out


def _screen_signature(screen: dict[str, Any]) -> str:
    if not screen:
        return ""
    w = screen.get("width", "")
    h = screen.get("height", "")
    cd = screen.get("colorDepth", "")
    pr = screen.get("pixelRatio", "")
    return f"{w}x{h}x{cd}x{pr}"


def sanitize_client_fingerprint(raw: dict | None) -> dict[str, Any]:
    """Bound and validate client-submitted fingerprint fields."""
    if not isinstance(raw, dict):
        raw = {}
    orientation = raw.get("orientation") if isinstance(raw.get("orientation"), dict) else {}
    screen = _normalize_screen(raw.get("screen"))
    languages = _normalize_languages(raw.get("languages"))
    if not languages and raw.get("language"):
        languages = _normalize_languages([raw.get("language")])

    out: dict[str, Any] = {
        "canvas_hash": _normalize_hex_hash(raw.get("canvas_hash")),
        "canvas_text_hash": _normalize_hex_hash(raw.get("canvas_text_hash")),
        "webgl_renderer": _clip_str(raw.get("webgl_renderer")),
        "webgl_vendor": _clip_str(raw.get("webgl_vendor")),
        "webgl_hash": _normalize_hex_hash(raw.get("webgl_hash")),
        "audio_hash": _normalize_hex_hash(raw.get("audio_hash")),
        "fonts_hash": _normalize_hex_hash(raw.get("fonts_hash")),
        "timezone": _clip_str(raw.get("timezone"), 80),
        "timezone_offset": _clip_int(raw.get("timezone_offset"), -840, 840),
        "languages": languages,
        "platform": _clip_str(raw.get("platform"), 64),
        "hardware_concurrency": _clip_int(raw.get("hardware_concurrency"), 1, 256),
        "device_memory": _clip_float(raw.get("device_memory"), 0.25, 512),
        "max_touch_points": _clip_int(raw.get("max_touch_points"), 0, 32),
        "color_gamut": _clip_str(raw.get("color_gamut"), 16),
        "plugins_count": _clip_int(raw.get("plugins_count"), 0, 512),
        "screen": screen,
        "screen_sig": _screen_signature(screen),
        "orientation": {
            "alpha": _clip_float(orientation.get("alpha"), -360, 360),
            "beta": _clip_float(orientation.get("beta"), -180, 180),
            "gamma": _clip_float(orientation.get("gamma"), -180, 180),
        },
    }
    # Drop empty orientation
    if not any(v is not None for v in out["orientation"].values()):
        out["orientation"] = {}
    return out


def _has_minimum_signals(cf: dict[str, Any]) -> bool:
    if cf.get("canvas_hash") or cf.get("canvas_text_hash"):
        return True
    if cf.get("webgl_hash") and cf.get("screen_sig"):
        return True
    if cf.get("webgl_renderer") and cf.get("audio_hash"):
        return True
    if cf.get("fonts_hash") and cf.get("timezone") and cf.get("screen_sig"):
        return True
    return False


def compute_visitor_fp_id(cf: dict[str, Any]) -> str | None:
    """Stable SHA-256 visitor id from normalized browser signals (no IP)."""
    if not _has_minimum_signals(cf):
        return None
    components = {
        "canvas": cf.get("canvas_hash") or "",
        "canvas2": cf.get("canvas_text_hash") or "",
        "webgl_renderer": cf.get("webgl_renderer") or "",
        "webgl_vendor": cf.get("webgl_vendor") or "",
        "webgl_hash": cf.get("webgl_hash") or "",
        "audio_hash": cf.get("audio_hash") or "",
        "fonts_hash": cf.get("fonts_hash") or "",
        "screen": cf.get("screen_sig") or "",
        "tz": cf.get("timezone") or "",
        "tz_off": cf.get("timezone_offset"),
        "langs": cf.get("languages") or [],
        "hw": cf.get("hardware_concurrency"),
        "mem": cf.get("device_memory"),
        "platform": cf.get("platform") or "",
        "touch": cf.get("max_touch_points"),
        "gamut": cf.get("color_gamut") or "",
    }
    canonical = json.dumps(components, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def visitor_fp_short(visitor_fp_id: str | None) -> str:
    if not visitor_fp_id:
        return ""
    return visitor_fp_id[:VISITOR_FP_SHORT_LEN]


def visitor_fp_filter_token(raw: str) -> str:
    """Normalize admin filter input to hex prefix/suffix."""
    s = (raw or "").strip().lower()
    s = re.sub(r"[^a-f0-9]", "", s)
    return s[:VISITOR_FP_ID_LEN]


def merge_client_fingerprints(old: dict | None, new: dict | None) -> dict:
    """Prefer richer new values without dropping stable fields from a prior capture."""
    base = sanitize_client_fingerprint(old)
    fresh = sanitize_client_fingerprint(new)
    skip = frozenset({"visit", "resolved_final_action", "capture_complete"})
    merged = dict(base)
    for key, val in fresh.items():
        if key in skip:
            continue
        if val is None or val == "" or val == [] or val == {}:
            continue
        if not merged.get(key):
            merged[key] = val
    return sanitize_client_fingerprint(merged)


def format_visitor_for_discord(visit: dict[str, Any]) -> str:
    if not visit.get("identified"):
        return "**Visitor:** unidentified (insufficient browser signals)"
    short = visit.get("visitor_fp_short") or "?"
    if visit.get("is_repeat"):
        parts = [f"**Visitor:** repeat — visit **#{visit.get('global_visit_number', '?')}** globally"]
        if visit.get("link_visit_number") is not None:
            parts.append(f"**#{visit['link_visit_number']}** on this link")
        parts.append(f"(`{short}`)")
        return " · ".join(parts)
    return f"**Visitor:** first visit (`{short}`)"
