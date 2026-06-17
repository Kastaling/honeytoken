"""Public Trap app on port 4040: catch-all, capture headers, fingerprint, jitter."""
import json
import os
import re
import random
import secrets
import time
from pathlib import Path
from flask import Flask, request, render_template, jsonify, send_from_directory
from fingerprint import build_fingerprint
from store import add_hit, get_hit_by_id, get_hit_capture_context, get_tracked_link, get_tracked_link_by_path, get_tracked_link_by_token, get_visitor_visit_stats, update_hit
from alerts import notify_hit
from hit_notifications import NOTIFICATION_PHASE_AFTER_CAPTURE, NOTIFICATION_PHASE_IMMEDIATE
from config_store import get_config, resolve_action_for_capture, describe_final_action_taken, normalize_action_settings, normalize_single_action
from visitor_fingerprint import (
    MAX_CLIENT_PAYLOAD_BYTES,
    compute_visitor_fp_id,
    merge_client_fingerprints,
    sanitize_client_fingerprint,
)
from geo import enrich_hit_location
from geoip2_lookup import get_lat_lng_city

app = Flask(__name__, template_folder="templates")
MEDIA_DIR = Path(os.environ.get("MEDIA_DIR", "/media"))

VALID_STATUS_CODES = (
    403, 404, 410, 412, 418,
    500, 501, 502, 503, 504, 505, 506, 507, 508,
)
STATUS_MESSAGES = {
    403: ("403 Forbidden", "Forbidden"),
    404: ("404 Not Found", "Not Found"),
    410: ("410 Gone", "Gone"),
    412: ("412 Precondition Failed", "Precondition Failed"),
    418: ("418 I'm a teapot", "I'm a teapot"),
    500: ("500 Internal Server Error", "Internal Server Error"),
    501: ("501 Not Implemented", "Not Implemented"),
    502: ("502 Bad Gateway", "Bad Gateway"),
    503: ("503 Service Unavailable", "Service Unavailable"),
    504: ("504 Gateway Timeout", "Gateway Timeout"),
    505: ("505 HTTP Version Not Supported", "HTTP Version Not Supported"),
    506: ("506 Variant Also Negotiates", "Variant Also Negotiates"),
    507: ("507 Insufficient Storage", "Insufficient Storage"),
    508: ("508 Loop Detected", "Loop Detected"),
}


def _real_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _request_host() -> str:
    """Host the client used: X-Forwarded-Host (when behind proxy) else Host."""
    host = request.headers.get("X-Forwarded-Host")
    if host:
        return host.split(",")[0].strip()
    return (request.headers.get("Host") or "").strip()


def _normalize_host(host: str) -> str:
    """Normalize host for config lookup (lowercase, strip)."""
    return (host or "").strip().lower()


def _settings_for_host(cfg: dict, host: str) -> dict:
    """Effective settings for this host: global defaults merged with per-host overrides."""
    effective = dict(cfg)
    h = _normalize_host(host)
    if h and isinstance(cfg.get("host_settings"), dict) and h in cfg["host_settings"]:
        effective.update(cfg["host_settings"][h])
    return effective


def _capture_headers() -> dict:
    return dict(request.headers)


def _nginx_context(code: int, hit_id: int) -> dict:
    title, message = STATUS_MESSAGES.get(code, STATUS_MESSAGES[404])
    return {"title": title, "code": code, "message": message, "hit_id": hit_id}


def _media_tab_config(s: dict) -> dict:
    """Build tab-title config for JSON response; mode 'none' means no tab behavior."""
    mode = (s.get("media_tab_mode") or "none").strip().lower()
    if mode not in ("none", "static", "scrolling", "rotating"):
        mode = "none"
    static_text = (s.get("media_tab_static_text") or "")[:500]
    scrolling_text = (s.get("media_tab_scrolling_text") or "")[:500]
    raw = (s.get("media_tab_rotating_messages") or "").strip()
    rotating = [line.strip()[:500] for line in raw.split("\n")[:20] if line.strip()]
    try:
        interval = max(1, min(60, int(s.get("media_tab_rotate_interval_sec", 3))))
    except (ValueError, TypeError):
        interval = 3
    return {
        "mode": mode,
        "static_text": static_text,
        "scrolling_text": scrolling_text,
        "rotating_messages": rotating,
        "rotate_interval_sec": interval,
    }


def _media_tab_script_inline(tab_config: dict) -> str:
    """Return a script tag that runs tab-title behavior; safe to append to HTML."""
    cfg_json = json.dumps(tab_config)
    return (
        "<script>(function(){"
        "var c=" + cfg_json + ";"
        "if(c.mode==='static'&&c.static_text){document.title=c.static_text;return;}"
        "if(c.mode==='scrolling'&&c.scrolling_text){"
        "var s=c.scrolling_text+' ';var i=0;"
        "setInterval(function(){document.title=s.slice(i)+s.slice(0,i);i=(i+1)%s.length;},150);"
        "return;}"
        "if(c.mode==='rotating'&&c.rotating_messages&&c.rotating_messages.length){"
        "var idx=0;var list=c.rotating_messages;var sec=(c.rotate_interval_sec||3)*1000;"
        "document.title=list[0];"
        "setInterval(function(){idx=(idx+1)%list.length;document.title=list[idx];},sec);"
        "}"
        "})();<\\/script>"
    )


def _youtube_embed_html(watch_url: str) -> str | None:
    """Build full-page HTML with YouTube iframe (autoplay=1, mute=1). Returns None if URL invalid."""
    if not watch_url or not watch_url.strip():
        return None
    url = watch_url.strip()
    video_id = None
    m = re.search(r"(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})", url)
    if m:
        video_id = m.group(1)
    if not video_id:
        return None
    embed_src = f"https://www.youtube.com/embed/{video_id}?autoplay=1&mute=1"
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title></title>"
        "<style>body{margin:0;background:#000;display:flex;align-items:center;justify-content:center;min-height:100vh;}"
        "iframe{width:100vw;height:100vh;border:none;}</style></head><body>"
        f"<iframe src='{embed_src}' allow='accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture' allowfullscreen></iframe>"
        "</body></html>"
    )


def _is_favicon(path: str) -> bool:
    """True if request is for favicon (do not record)."""
    p = (path or "").strip().lower().lstrip("/")
    return p == "favicon.ico" or p.endswith("/favicon.ico")


def _link_token_from_path(path: str) -> str | None:
    """Return token from reserved /l/<token> path, if present."""
    parts = (path or "").strip("/").split("/", 2)
    if len(parts) == 2 and parts[0] == "l" and parts[1]:
        return parts[1]
    return None


def _response_for_settings(s: dict):
    """Build the final-action JSON response for host or per-link settings."""
    redirect_url = (s.get("default_redirect_url") or "").strip()
    if redirect_url:
        return jsonify(action="redirect", redirect_url=redirect_url)
    media_url = (s.get("media_url") or "").strip()
    media_type = (s.get("media_type") or "").strip().lower()
    if media_url and media_type in ("image", "gif", "video", "youtube"):
        fallback_html = render_template("nginx_error_static.html", **_nginx_context(404, 0))
        tab_config = _media_tab_config(s)
        if media_type == "youtube":
            embed_html = _youtube_embed_html(media_url)
            if embed_html:
                if tab_config.get("mode") != "none":
                    embed_html = embed_html.replace("</body></html>", _media_tab_script_inline(tab_config) + "</body></html>")
                return jsonify(
                    action="media",
                    media_type="youtube",
                    media_url=media_url,
                    embed_html=embed_html,
                    fallback_html=fallback_html,
                    media_tab=tab_config,
                )
        return jsonify(
            action="media",
            media_type=media_type,
            media_url=media_url,
            fallback_html=fallback_html,
            media_tab=tab_config,
        )
    status_code = s.get("status_code", 404)
    if status_code not in VALID_STATUS_CODES:
        status_code = 404
    error_html = render_template("nginx_error_static.html", **_nginx_context(status_code, 0))
    return (
        jsonify(action="error", html=error_html, status_code=status_code),
        status_code,
        {"Content-Type": "application/json; charset=utf-8"},
    )


@app.route("/media/<path:filepath>", methods=["GET"])
def serve_media(filepath: str):
    """Serve media files from MEDIA_DIR (mounted volume). No path traversal."""
    if ".." in filepath or filepath.startswith("/"):
        return "", 404
    if not MEDIA_DIR.is_dir():
        return "", 404
    full = (MEDIA_DIR / filepath).resolve()
    try:
        full.relative_to(MEDIA_DIR.resolve())
    except ValueError:
        return "", 404
    if not full.is_file():
        return "", 404
    return send_from_directory(str(MEDIA_DIR), filepath)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"])
def catch_all(path):
    time.sleep(random.uniform(0.5, 2.0))

    req_path = "/" + path if path else "/"
    if _is_favicon(path):
        return (
            render_template("trap_loading.html", hit_id=0, capture_token=""),
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    tracked_link = None
    link_token = _link_token_from_path(path)
    if link_token:
        tracked_link = get_tracked_link_by_token(link_token)
    if not tracked_link:
        tracked_link = get_tracked_link_by_path(_request_host(), req_path)
    ip = _real_ip()
    all_headers = _capture_headers()
    user_agent = request.headers.get("User-Agent")
    accept_language = request.headers.get("Accept-Language")
    connection = request.headers.get("Connection")
    fingerprint = build_fingerprint(user_agent or "", accept_language or "", connection or "")

    geo = get_lat_lng_city(ip)
    record = {
        "ip": ip,
        "host": _request_host(),
        "path": req_path,
        "method": request.method,
        "headers": all_headers,
        "fingerprint": fingerprint,
        "query_string": request.query_string.decode("utf-8") if request.query_string else None,
        "latitude": geo.get("latitude") if geo else None,
        "longitude": geo.get("longitude") if geo else None,
        "city": geo.get("city") if geo else None,
        "location_display": geo.get("location_display") if geo else None,
        "location": (
            {"city": geo.get("city"), "region": geo.get("region"), "country": geo.get("country")}
            if geo else {}
        ),
        "link_id": tracked_link.get("_id") if tracked_link else None,
        "capture_token": secrets.token_urlsafe(24),
    }
    hit_id = add_hit(record)
    notify_hit({**record, "_id": hit_id}, phase=NOTIFICATION_PHASE_IMMEDIATE)
    enrich_hit_location(hit_id, ip)

    return (
        render_template("trap_loading.html", hit_id=hit_id, capture_token=record["capture_token"]),
        200,
        {"Content-Type": "text/html; charset=utf-8"},
    )


@app.route("/capture", methods=["POST"])
def capture():
    # Jitter first so the final command is delayed before the client receives it
    time.sleep(random.uniform(0.5, 2.0))

    try:
        raw_body = request.get_data(cache=True) or b""
        if len(raw_body) > MAX_CLIENT_PAYLOAD_BYTES:
            data = {}
        else:
            data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    hit_id = data.get("hit_id")
    client_fp = sanitize_client_fingerprint(data if isinstance(data, dict) else {})
    hit_context = None
    if hit_id is not None:
        try:
            hit_context = get_hit_capture_context(int(hit_id))
        except (TypeError, ValueError):
            hit_context = None
    capture_token = str(data.get("capture_token") or "")
    host = _request_host()
    cfg = get_config()
    action_settings = _settings_for_host(cfg, host)
    if hit_context and hit_context.get("link_id"):
        link = get_tracked_link(int(hit_context["link_id"]))
        if link:
            action_settings = link.get("settings") or action_settings
    action_settings = normalize_action_settings(action_settings)

    existing_hit = None
    if hit_id is not None:
        try:
            existing_hit = get_hit_by_id(int(hit_id))
        except (TypeError, ValueError):
            existing_hit = None

    cached_resolved = None
    if existing_hit and isinstance(existing_hit.get("client_fingerprint"), dict):
        cached = existing_hit["client_fingerprint"].get("resolved_final_action")
        if isinstance(cached, dict):
            cached_resolved = normalize_single_action(cached)

    if cached_resolved:
        resolved_action = cached_resolved
    else:
        resolved_action = resolve_action_for_capture(action_settings)

    if hit_context:
        expected = str(hit_context.get("capture_token") or "")
        capture_token_valid = bool(expected) and secrets.compare_digest(expected, capture_token)
        if capture_token_valid:
            hid = int(hit_context["_id"])
            link_id = hit_context.get("link_id")
            prior_cf = (existing_hit or {}).get("client_fingerprint") if isinstance((existing_hit or {}).get("client_fingerprint"), dict) else {}
            already_captured = bool(prior_cf.get("capture_complete"))
            client_fp = merge_client_fingerprints(prior_cf, client_fp)
            client_fp["resolved_final_action"] = resolved_action
            client_fp["capture_complete"] = True
            visitor_fp_id = compute_visitor_fp_id(client_fp)
            visit_stats = get_visitor_visit_stats(visitor_fp_id, hid, link_id)
            client_fp["visit"] = visit_stats
            update_hit(hid, {"client_fingerprint": client_fp, "visitor_fp_id": visitor_fp_id})
            if not already_captured:
                full_hit = get_hit_by_id(hid)
                if full_hit:
                    full_hit["final_action"] = describe_final_action_taken(action_settings, resolved_action)
                    full_hit["visitor_visit"] = visit_stats
                    notify_hit(full_hit, phase=NOTIFICATION_PHASE_AFTER_CAPTURE)

    return _response_for_settings(resolved_action)


@app.route("/error/<int:code>")
def error_page(code):
    """Serve static fake error page (no script). Used after /capture returns action=error."""
    if code not in VALID_STATUS_CODES:
        code = 404
    return (
        render_template("nginx_error_static.html", **_nginx_context(code, 0)),
        code,
        {"Content-Type": "text/html; charset=utf-8"},
    )
