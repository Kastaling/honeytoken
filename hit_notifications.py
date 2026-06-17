"""
Configurable hit notifications: pluggable channels (Discord webhook today), filter rules, phases.

Phases:
  immediate — right after the hit is stored (no client GPU/canvas yet).
  after_capture — after /capture persists client_fingerprint (GPU/canvas filters apply).
"""
from __future__ import annotations

import re
import secrets
import threading
from typing import Any, Callable
from urllib.parse import urlparse

import requests

from visitor_fingerprint import format_visitor_for_discord, visitor_fp_short

# Extensibility: register additional backends at startup via register_hit_notification_channel.
_CHANNEL_SENDERS: dict[str, Callable[[dict[str, Any], dict[str, Any], str], None]] = {}

NOTIFICATION_PHASE_IMMEDIATE = "immediate"
NOTIFICATION_PHASE_AFTER_CAPTURE = "after_capture"

VALID_TRIGGERS = (NOTIFICATION_PHASE_IMMEDIATE, NOTIFICATION_PHASE_AFTER_CAPTURE)
FILTER_TRUTH = ("any", "yes", "no")

DISCORD_WEBHOOK_PATH_PREFIX = "/api/webhooks/"
ALLOWED_DISCORD_WEBHOOK_NETLOCS = frozenset(
    {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"}
)
SNOWFLAKE_RE = re.compile(r"^\d{17,22}$")
MAX_RULES = 50
WEBHOOK_URL_MAX_LEN = 512


def _clean_discord_webhook_url(raw: str) -> str:
    url = (raw or "").strip()[:WEBHOOK_URL_MAX_LEN]
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return ""
    host = (parsed.netloc or "").split(":")[0].lower()
    if host not in ALLOWED_DISCORD_WEBHOOK_NETLOCS:
        return ""
    path = parsed.path or ""
    if not path.startswith(DISCORD_WEBHOOK_PATH_PREFIX):
        return ""
    # Path must look like /api/webhooks/{id}/{token}
    parts = path.rstrip("/").split("/")
    if len(parts) < 5:
        return ""
    return url


def _normalize_snowflake_list(raw: Any, *, max_items: int = 25) -> list[str]:
    out: list[str] = []
    if isinstance(raw, list):
        items = raw[:max_items]
    elif isinstance(raw, str):
        items = re.split(r"[\s,]+", raw.strip())[:max_items]
    else:
        return []
    for x in items:
        s = str(x).strip()
        if SNOWFLAKE_RE.match(s):
            out.append(s)
    return out


def _normalize_hosts(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for h in raw[:64]:
        hs = str(h).strip().lower()[:255]
        if hs:
            out.append(hs)
    return out


def _normalize_link_ids(raw: Any) -> list[int]:
    if not isinstance(raw, list):
        return []
    out: list[int] = []
    for x in raw[:64]:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            continue
    return sorted(set(i for i in out if i > 0))


def _strip_link_token_fragment(s: str) -> str:
    """Turn pasted paths or URLs into a candidate token string."""
    s = (s or "").strip()
    if not s:
        return ""
    s = s.split("?", 1)[0].split("#", 1)[0].strip()
    low = s.lower()
    if "/l/" in low:
        idx = low.rfind("/l/")
        s = s[idx + 3 :]
    s = s.strip().strip("/")
    return s[:96]


def _normalize_link_tokens(raw: Any) -> list[str]:
    """Normalize tracked-link tokens (Grabify-style `/l/{token}` segments)."""
    from store import LINK_TOKEN_RE, RESERVED_LINK_TOKENS

    if isinstance(raw, list):
        candidates = [str(x).strip() for x in raw[:50]]
    elif isinstance(raw, str):
        candidates = re.split(r"[\s,]+", raw.strip())[:50]
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for c in candidates:
        frag = _strip_link_token_fragment(c)
        if not frag or frag.lower() in RESERVED_LINK_TOKENS:
            continue
        if not LINK_TOKEN_RE.fullmatch(frag):
            continue
        if frag not in seen:
            seen.add(frag)
            out.append(frag)
    return out


def _normalize_filter_truth(val: Any) -> str:
    s = (val if isinstance(val, str) else str(val or "")).strip().lower()
    return s if s in FILTER_TRUTH else "any"


def _normalize_filters(raw: dict | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    hosts = _normalize_hosts(raw.get("hosts"))
    path_contains = (raw.get("path_contains") or "").strip()[:500]
    link_ids = _normalize_link_ids(raw.get("link_ids"))
    link_tokens = _normalize_link_tokens(raw.get("link_tokens"))
    gpu = _normalize_filter_truth(raw.get("gpu"))
    canvas = _normalize_filter_truth(raw.get("canvas"))
    return {
        "hosts": hosts,
        "path_contains": path_contains,
        "link_ids": link_ids,
        "link_tokens": link_tokens,
        "gpu": gpu,
        "canvas": canvas,
    }


def _allowed_link_ids_from_filters(filters: dict[str, Any]) -> frozenset[int] | None:
    """If link filtering is active, return allowed DB link ids (numeric + resolved tokens)."""
    ids_list = filters.get("link_ids") or []
    tokens = filters.get("link_tokens") or []
    if not ids_list and not tokens:
        return None
    from store import get_tracked_link_by_token

    ids: set[int] = set(ids_list)
    for tok in tokens:
        row = get_tracked_link_by_token(tok)
        if row and row.get("_id") is not None:
            try:
                ids.add(int(row["_id"]))
            except (TypeError, ValueError):
                continue
    return frozenset(ids)


def _normalize_channel(raw: dict | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    ctype = (raw.get("type") or "discord_webhook").strip().lower()
    if ctype != "discord_webhook":
        # Preserve unknown types for forward compatibility (no sender registered).
        return {"type": ctype, "config": dict(raw)}
    username = (raw.get("username") or "").strip()[:80]
    return {
        "type": "discord_webhook",
        "webhook_url": _clean_discord_webhook_url(raw.get("webhook_url") or ""),
        "mention_user_ids": _normalize_snowflake_list(raw.get("mention_user_ids")),
        "mention_role_ids": _normalize_snowflake_list(raw.get("mention_role_ids")),
        "username": username or None,
    }


def normalize_notification_rules(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw[:MAX_RULES]:
        if not isinstance(entry, dict):
            continue
        rid = str(entry.get("id") or "").strip()[:64]
        if not rid:
            rid = secrets.token_hex(6)
        enabled = bool(entry.get("enabled", True))
        name = (entry.get("name") or "").strip()[:120]
        trigger = (entry.get("trigger") or NOTIFICATION_PHASE_IMMEDIATE).strip().lower()
        if trigger not in VALID_TRIGGERS:
            trigger = NOTIFICATION_PHASE_IMMEDIATE
        filters = _normalize_filters(entry.get("filters"))
        # Client-only filters require after_capture.
        if filters["gpu"] != "any" or filters["canvas"] != "any":
            trigger = NOTIFICATION_PHASE_AFTER_CAPTURE
        channel = _normalize_channel(entry.get("channel"))
        # Drop unusable discord rules missing URL when enabled (avoid silent failures).
        if enabled and channel.get("type") == "discord_webhook" and not channel.get("webhook_url"):
            enabled = False
        out.append(
            {
                "id": rid,
                "enabled": enabled,
                "name": name,
                "trigger": trigger,
                "filters": filters,
                "channel": channel,
            }
        )
    return out


def _gpu_detected(client_fp: dict) -> bool:
    if not isinstance(client_fp, dict):
        return False
    r = client_fp.get("webgl_renderer")
    return bool(str(r).strip()) if r is not None else False


def _canvas_detected(client_fp: dict) -> bool:
    if not isinstance(client_fp, dict):
        return False
    h = client_fp.get("canvas_hash")
    return bool(str(h).strip()) if h is not None else False


def hit_matches_filters(hit: dict[str, Any], filters: dict[str, Any], phase: str) -> bool:
    hosts = filters.get("hosts") or []
    if hosts:
        hh = (hit.get("host") or "").strip().lower()
        if hh not in set(hosts):
            return False
    pc = (filters.get("path_contains") or "").strip()
    if pc:
        path = (hit.get("path") or "")
        if pc.lower() not in path.lower():
            return False
    allowed_links = _allowed_link_ids_from_filters(filters)
    if allowed_links is not None:
        lid = hit.get("link_id")
        try:
            lid_int = int(lid) if lid is not None else None
        except (TypeError, ValueError):
            lid_int = None
        if lid_int not in allowed_links:
            return False

    cf = hit.get("client_fingerprint") if isinstance(hit.get("client_fingerprint"), dict) else {}

    for key, detector in (("gpu", _gpu_detected), ("canvas", _canvas_detected)):
        want = filters.get(key) or "any"
        if want == "any":
            continue
        # immediate phase cannot evaluate client signals reliably
        if phase == NOTIFICATION_PHASE_IMMEDIATE:
            return False
        has = detector(cf)
        if want == "yes" and not has:
            return False
        if want == "no" and has:
            return False

    return True


def _mention_content(channel: dict[str, Any]) -> str | None:
    parts: list[str] = []
    for uid in channel.get("mention_user_ids") or []:
        parts.append(f"<@{uid}>")
    for rid in channel.get("mention_role_ids") or []:
        parts.append(f"<@&{rid}>")
    if not parts:
        return None
    return " ".join(parts)


def _safe_hit_summary(hit: dict[str, Any]) -> dict[str, Any]:
    """Subset suitable for external webhooks (no secrets)."""
    fp = hit.get("fingerprint") if isinstance(hit.get("fingerprint"), dict) else {}
    cf = hit.get("client_fingerprint") if isinstance(hit.get("client_fingerprint"), dict) else {}
    return {
        "_id": hit.get("_id"),
        "ip": hit.get("ip"),
        "host": hit.get("host"),
        "path": hit.get("path"),
        "method": hit.get("method"),
        "query_string": hit.get("query_string"),
        "location_display": hit.get("location_display"),
        "city": hit.get("city"),
        "link_id": hit.get("link_id"),
        "os_guess": fp.get("os_guess"),
        "browser_guess": fp.get("browser_guess"),
        "user_agent_raw": (fp.get("user_agent_raw") or "")[:280],
        "gpu_renderer": (cf.get("webgl_renderer") or "")[:200],
        "canvas_hash": (cf.get("canvas_hash") or "")[:120],
        "visitor_fp_short": visitor_fp_short(hit.get("visitor_fp_id") or (cf.get("visit") or {}).get("visitor_fp_id")),
    }


def _format_final_action_line(final_action: dict[str, Any]) -> str:
    """Discord markdown line for the resolved final action."""
    mode = (final_action.get("mode") or "?").strip().lower()
    label = (final_action.get("label") or "").strip()
    prefix = f"{label}: " if label else ""
    if mode == "redirect":
        body = f"redirect → `{final_action.get('detail') or '?'}`"
    elif mode == "media":
        mt = (final_action.get("media_type") or "media").strip().lower()
        fn = (final_action.get("media_filename") or final_action.get("detail") or "?").strip()
        body = f"media ({mt}) — file `{fn}`"
    else:
        body = f"error HTTP {final_action.get('detail') or '?'}"
    if final_action.get("random"):
        pool = final_action.get("pool_size") or "?"
        body += f" *(random, 1 of {pool})*"
    return f"**Final action:** {prefix}{body}"


def _discord_embed_body(hit: dict[str, Any], rule_name: str, phase: str) -> dict[str, Any]:
    s = _safe_hit_summary(hit)
    lines = []
    if hit.get("_notification_test"):
        lines.append("> **Test preview** — sample visitor data (not a real trap hit).\n")
    lines.extend(
        [
            f"**IP:** `{s.get('ip') or '?'}`",
            f"**Host:** `{s.get('host') or '?'}`",
            f"**Path:** `{s.get('path') or '?'}`",
            f"**Method:** `{s.get('method') or '?'}`",
        ]
    )
    if s.get("location_display"):
        lines.append(f"**Location:** {s['location_display']}")
    if s.get("link_id"):
        lines.append(f"**Link ID:** `{s['link_id']}`")
    lines.extend(
        [
            f"**OS:** {s.get('os_guess') or '?'}",
            f"**Browser:** {s.get('browser_guess') or '?'}",
        ]
    )
    gr = s.get("gpu_renderer") or ""
    lines.append(f"**GPU (WebGL):** `{gr}`" if gr else "**GPU (WebGL):** *(none)*")
    ch = s.get("canvas_hash") or ""
    lines.append(f"**Canvas:** `{ch[:40]}…`" if len(ch) > 40 else f"**Canvas:** `{ch or '(none)'}`")
    fa = hit.get("final_action")
    if phase == NOTIFICATION_PHASE_AFTER_CAPTURE and isinstance(fa, dict) and fa.get("mode"):
        lines.append(_format_final_action_line(fa))
    visit = hit.get("visitor_visit")
    if not isinstance(visit, dict) or not visit:
        cf_visit = (hit.get("client_fingerprint") or {}).get("visit") if isinstance(hit.get("client_fingerprint"), dict) else None
        visit = cf_visit if isinstance(cf_visit, dict) else {}
    if phase == NOTIFICATION_PHASE_AFTER_CAPTURE:
        lines.append(format_visitor_for_discord(visit))
    lines.append(f"**Phase:** `{phase}`")
    title = "Honeytoken hit"
    if rule_name:
        title = f"{title}: {rule_name}"
    embed: dict[str, Any] = {
        "title": title,
        "description": "\n".join(lines),
        "color": 0xFF6600,
    }
    if hit.get("_notification_test"):
        embed["footer"] = {"text": "Honeytoken · test preview"}
    return {
        "embeds": [
            embed,
        ]
    }


def sample_hit_for_notification_test(rule: dict[str, Any]) -> dict[str, Any]:
    """Synthetic hit shaped like store output; reflects common filters for realism."""
    filters = rule.get("filters") or {}
    hosts = filters.get("hosts") or []
    host = hosts[0] if hosts else "visitor.example.com"
    lids = filters.get("link_ids") or []
    link_id = lids[0] if lids else None
    tokens = filters.get("link_tokens") or []
    if link_id is None and tokens:
        try:
            from store import get_tracked_link_by_token

            row = get_tracked_link_by_token(str(tokens[0]))
            if row and row.get("_id") is not None:
                link_id = int(row["_id"])
        except (TypeError, ValueError):
            link_id = None
    pc = (filters.get("path_contains") or "").strip()
    path = "/l/preview-token"
    if pc:
        path = "/" + pc.lstrip("/")[:2047]
    path = path[:2048]
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    return {
        "_id": 0,
        "_notification_test": True,
        "ip": "203.0.113.7",
        "host": host,
        "path": path,
        "method": "GET",
        "headers": {},
        "fingerprint": {
            "os_guess": "Windows",
            "browser_guess": "Chrome",
            "user_agent_raw": ua,
        },
        "query_string": None,
        "location_display": "Austin, Texas, United States",
        "city": "Austin",
        "link_id": link_id,
        "client_fingerprint": {
            "webgl_renderer": (
                "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device "
                "(Subzero) (0x0000C0DE)), SwiftShader driver)"
            ),
            "canvas_hash": "9f3e2b1a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2",
        },
        "final_action": {
            "mode": "media",
            "random": True,
            "pool_size": 3,
            "label": "Preview clip",
            "detail": "honeypot-bait.mp4",
            "media_type": "video",
            "media_filename": "honeypot-bait.mp4",
        },
        "visitor_fp_id": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "visitor_visit": {
            "identified": True,
            "visitor_fp_id": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
            "visitor_fp_short": "a1b2c3d4e5f6",
            "global_prior_visits": 2,
            "global_visit_number": 3,
            "link_prior_visits": 1,
            "link_visit_number": 2,
            "is_repeat": True,
            "is_repeat_link": True,
        },
    }


def discord_webhook_payload(hit: dict[str, Any], rule: dict[str, Any], phase: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    """Return (webhook_url, json_payload) or (None, None) if misconfigured."""
    channel = rule.get("channel") or {}
    url = channel.get("webhook_url") or ""
    if not url:
        return None, None
    payload_body = _discord_embed_body(hit, rule.get("name") or "", phase)
    embed = payload_body["embeds"][0]
    payload: dict[str, Any] = {"embeds": [embed]}
    mentions = _mention_content(channel)
    if mentions:
        payload["content"] = mentions
        payload["allowed_mentions"] = {
            "parse": [],
            "users": list(channel.get("mention_user_ids") or []),
            "roles": list(channel.get("mention_role_ids") or []),
        }
    uname = channel.get("username")
    if uname:
        payload["username"] = uname
    return url, payload


def send_discord_webhook(hit: dict[str, Any], rule: dict[str, Any], phase: str) -> None:
    url, payload = discord_webhook_payload(hit, rule, phase)
    if not url or not payload:
        return
    try:
        requests.post(url, json=payload, timeout=12)
    except Exception:
        pass


def send_discord_notification_test(rule: dict[str, Any]) -> tuple[bool, str]:
    """POST one preview embed to this rule's Discord webhook. Returns (success, reason_code)."""
    channel = rule.get("channel") or {}
    if channel.get("type") != "discord_webhook":
        return False, "unsupported_channel"
    phase = rule.get("trigger") or NOTIFICATION_PHASE_IMMEDIATE
    hit = sample_hit_for_notification_test(rule)
    url, payload = discord_webhook_payload(hit, rule, phase)
    if not url or not payload:
        return False, "no_webhook"
    try:
        r = requests.post(url, json=payload, timeout=15)
        if 200 <= r.status_code < 300:
            return True, "ok"
        return False, f"discord_http_{r.status_code}"
    except requests.RequestException:
        return False, "network_error"


def register_hit_notification_channel(
    channel_type: str,
    sender: Callable[[dict[str, Any], dict[str, Any], str], None],
) -> None:
    """Register a sender for config channel.type (hit, rule, phase)."""
    key = (channel_type or "").strip().lower()
    if key:
        _CHANNEL_SENDERS[key] = sender


def _send_rule(hit: dict[str, Any], rule: dict[str, Any], phase: str) -> None:
    channel = rule.get("channel") or {}
    ctype = (channel.get("type") or "").strip().lower()
    sender = _CHANNEL_SENDERS.get(ctype)
    if sender:
        sender(hit, rule, phase)


register_hit_notification_channel("discord_webhook", send_discord_webhook)


def dispatch_hit_notifications(hit: dict[str, Any], phase: str, cfg: dict[str, Any]) -> None:
    """Evaluate enabled rules for this phase and send asynchronously."""
    if phase not in VALID_TRIGGERS:
        return
    rules = cfg.get("notification_rules") or []
    if not isinstance(rules, list):
        return

    to_run: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("enabled"):
            continue
        if rule.get("trigger") != phase:
            continue
        if not hit_matches_filters(hit, rule.get("filters") or {}, phase):
            continue
        to_run.append(rule)

    if not to_run:
        return

    def _run():
        for rule in to_run:
            try:
                _send_rule(hit, rule, phase)
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
