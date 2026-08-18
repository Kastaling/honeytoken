"""Private Admin Dashboard on port 4090; auth via ADMIN_USER / ADMIN_PASS."""
import json
import os
import secrets
import time
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, request, Response, render_template_string, redirect, jsonify, make_response
from store import (
    create_tracked_link,
    get_hits,
    get_hits_count,
    delete_hit,
    delete_hits,
    delete_all,
    get_geo_stats,
    get_distinct_hosts,
    get_tracked_link_stats,
    LINK_TOKEN_MAX_LEN,
    list_tracked_links,
    RESERVED_LINK_TOKENS,
    update_tracked_link,
)
from config_store import (
    ACTION_URL_MAX_LEN,
    DEFAULT_TIMEZONE,
    get_config,
    MAX_FINAL_ACTIONS,
    normalize_action_settings,
    save_config,
    VALID_STATUS_CODES,
)
from admin_final_actions import FINAL_ACTIONS_CSS, FINAL_ACTION_ACTION_TEMPLATE, FINAL_ACTIONS_JS
from hit_notifications import normalize_notification_rules, send_discord_notification_test

app = Flask(__name__)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
ROOT_DOMAIN = os.environ.get("ROOT_DOMAIN", "example.com")
MEDIA_DIR = Path(os.environ.get("MEDIA_DIR", "/media"))
_DEFAULT_ADMIN_PASSWORDS = frozenset({"", "changeme"})

_NR_TEST_LAST_BY_IP: dict[str, float] = {}
_NR_TEST_COOLDOWN_SEC = 8.0


def _notification_rule_test_rate_ok(ip: str) -> bool:
    """Throttle test webhook spam per client IP."""
    now = time.monotonic()
    key = ip or "unknown"
    last = _NR_TEST_LAST_BY_IP.get(key, 0.0)
    if now - last < _NR_TEST_COOLDOWN_SEC:
        return False
    _NR_TEST_LAST_BY_IP[key] = now
    if len(_NR_TEST_LAST_BY_IP) > 2000:
        _NR_TEST_LAST_BY_IP.clear()
    return True


MEDIA_EXTENSIONS = frozenset(
    ".mp4 .webm .mov .ogg .m4v .mkv .avi .jpg .jpeg .png .gif .webp".split()
)

STATUS_OPTIONS = [
    (403, "403 Forbidden"),
    (404, "404 Not Found"),
    (410, "410 Gone"),
    (412, "412 Precondition Failed"),
    (418, "418 I'm a teapot"),
    (500, "500 Internal Server Error"),
    (501, "501 Not Implemented"),
    (502, "502 Bad Gateway"),
    (503, "503 Service Unavailable"),
    (504, "504 Gateway Timeout"),
    (505, "505 HTTP Version Not Supported"),
    (506, "506 Variant Also Negotiates"),
    (507, "507 Insufficient Storage"),
    (508, "508 Loop Detected"),
]


def validate_admin_auth_config() -> None:
    """Refuse to start with missing or default admin credentials."""
    if ADMIN_PASS in _DEFAULT_ADMIN_PASSWORDS:
        raise SystemExit(
            "ADMIN_PASS must be set to a strong, non-default password (not empty or 'changeme')."
        )


def _check_auth():
    auth = request.authorization
    if not auth:
        return False
    user_ok = secrets.compare_digest(auth.username or "", ADMIN_USER)
    pass_ok = secrets.compare_digest(auth.password or "", ADMIN_PASS)
    return user_ok and pass_ok


def _auth_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not _check_auth():
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Admin Dashboard"'},
            )
        return f(*args, **kwargs)
    return wrapped


def _list_media_files(max_depth: int = 3) -> list[str]:
    """Return relative paths of media files under MEDIA_DIR (recursive, up to max_depth)."""
    if not MEDIA_DIR.is_dir():
        return []
    out = []
    try:
        for root, _, files in os.walk(MEDIA_DIR, topdown=True):
            depth = len(Path(root).relative_to(MEDIA_DIR).parts)
            if depth >= max_depth:
                continue
            for f in files:
                if Path(f).suffix.lower() in MEDIA_EXTENSIONS:
                    rel = Path(root) / f
                    out.append(str(rel.relative_to(MEDIA_DIR)))
    except (ValueError, OSError):
        pass
    return sorted(out)


def _location_str(h):
    # Prefer GeoIP2 formatted string, then build from location JSON (ip-api)
    display = h.get("location_display")
    if display and str(display).strip():
        return display.strip()
    loc = h.get("location") or {}
    if not loc:
        return "—"
    parts = [p for p in (loc.get("city"), loc.get("region"), loc.get("country")) if p]
    return ", ".join(parts) if parts else (loc.get("country") or "—")


def _gpu_str(h):
    cf = h.get("client_fingerprint") or {}
    return (cf.get("webgl_renderer") or "—")[:48]


def _fingerprint_str(h):
    cf = h.get("client_fingerprint") or {}
    return cf.get("canvas_hash") or "—"


def _visitor_display(h):
    """Return (label, full_fp_id, visit_dict) for dashboard visitor column."""
    cf = h.get("client_fingerprint") or {}
    visit = cf.get("visit") if isinstance(cf.get("visit"), dict) else {}
    fp = (h.get("visitor_fp_id") or visit.get("visitor_fp_id") or "").strip()
    if not fp:
        return "—", "", {}
    num = visit.get("global_visit_number")
    if visit.get("is_repeat") and num:
        label = f"repeat #{num}"
    elif num:
        label = f"#{num}"
    else:
        label = fp[:12]
    return label, fp, visit


def _host_display(h):
    """Return (host_string, css_class) for badge styling."""
    host = (h.get("host") or "").strip()
    if not host:
        return "—", ""
    root = _clean_host_input(ROOT_DOMAIN)
    if root and host.lower() == root:
        return host, "host-badge host-badge-primary"
    return host, "host-badge"


def _clean_host_input(host: str) -> str:
    """Normalize an admin-entered host without allowing a scheme/path."""
    h = (host or "").strip().lower()
    if h.startswith("http://"):
        h = h[7:]
    elif h.startswith("https://"):
        h = h[8:]
    return h.split("/", 1)[0][:255]


def _available_link_hosts(cfg: dict) -> list[str]:
    hosts = {_clean_host_input(ROOT_DOMAIN)}
    hosts.update(_clean_host_input(h) for h in get_distinct_hosts() if h)
    hosts.update(_clean_host_input(h) for h in (cfg.get("host_settings") or {}).keys())
    return sorted(h for h in hosts if h)


def _effective_action_settings_for_host(cfg: dict, host: str) -> dict:
    effective = dict(cfg)
    normalized_host = _clean_host_input(host)
    host_settings = cfg.get("host_settings") or {}
    if normalized_host in host_settings:
        effective.update(host_settings[normalized_host])
    return normalize_action_settings(effective)


def _action_settings_from_json(raw: str) -> dict | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return normalize_action_settings(parsed)


def _action_settings_from_form(form) -> dict:
    from_json = _action_settings_from_json(form.get("action_settings_json"))
    if from_json is not None:
        return from_json
    return normalize_action_settings({
        "mode": form.get("mode"),
        "default_redirect_url": form.get("default_redirect_url"),
        "media_url": form.get("media_url"),
        "media_type": form.get("media_type"),
        "media_tab_mode": form.get("media_tab_mode"),
        "media_tab_static_text": form.get("media_tab_static_text"),
        "media_tab_scrolling_text": form.get("media_tab_scrolling_text"),
        "media_tab_rotating_messages": form.get("media_tab_rotating_messages"),
        "media_tab_rotate_interval_sec": form.get("media_tab_rotate_interval_sec"),
        "status_code": form.get("status_code"),
    })


def _external_scheme() -> str:
    scheme = (request.headers.get("X-Forwarded-Proto") or request.scheme or "https").split(",", 1)[0].strip().lower()
    return scheme if scheme in ("http", "https") else "https"


def _tracked_link_public_scheme() -> str:
    """HTTPS for honeypot links in admin UI (containers often see HTTP; public URL is HTTPS)."""
    scheme = (
        os.environ.get("TRACKED_LINK_PUBLIC_SCHEME")
        or os.environ.get("PUBLIC_URL_SCHEME")
        or "https"
    ).strip().lower()
    return scheme if scheme in ("http", "https") else "https"


def _tracked_link_url(host: str, path: str) -> str:
    return f"{_tracked_link_public_scheme()}://{_clean_host_input(host)}{path or ''}"


def _format_ts_readable(ts, tz_name=DEFAULT_TIMEZONE):
    """Format ISO UTC timestamp in the given timezone, e.g. 'Mar 10, 2026, 6:24:31 AM'."""
    if not ts or not isinstance(ts, str):
        return "—"
    s = (ts.strip() or "").replace("Z", "+00:00")
    try:
        dt_utc = datetime.fromisoformat(s[:26].rstrip("Z")).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return "—"
    try:
        tz = ZoneInfo(tz_name)
    except (ValueError, Exception):
        tz = timezone.utc
    local = dt_utc.astimezone(tz)
    return local.strftime("%b %d, %Y, %I:%M:%S %p")


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Honeytoken Admin – {{ domain }}</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="">
  <style>
    :root { --bg: #0a0a0b; --surface: #141416; --border: #27272a; --muted: #71717a; --text: #fafafa; --accent: #3b82f6; --green: #22c55e; --amber: #f59e0b; --purple: #a78bfa; }
    * { box-sizing: border-box; }
    body { font-family: 'Inter', ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); min-height: 100vh; }
    .wrap { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
    header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
    h1 { font-size: 1.35rem; font-weight: 600; margin: 0; letter-spacing: -0.02em; }
    nav { display: flex; gap: 1rem; align-items: center; }
    nav a { color: var(--muted); text-decoration: none; font-size: 0.875rem; }
    nav a:hover { color: var(--accent); }
    .badge { background: var(--surface); color: var(--muted); font-size: 0.75rem; padding: 0.25rem 0.5rem; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
    th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
    tbody tr { transition: background 0.15s; }
    tbody tr:hover { background: var(--surface); }
    tr.data-row { cursor: pointer; }
    tr.data-row.selected { background: rgba(59, 130, 246, 0.08); }
    .ip { font-family: ui-monospace, monospace; color: var(--amber); }
    .path { font-family: ui-monospace, monospace; color: var(--purple); word-break: break-all; max-width: 200px; }
    .location { color: var(--green); }
    .gpu { font-size: 0.75rem; color: var(--muted); max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fp { font-family: ui-monospace, monospace; font-size: 0.75rem; color: var(--muted); }
    .visitor { font-family: ui-monospace, monospace; font-size: 0.75rem; }
    .visitor a { color: var(--green); text-decoration: none; }
    .visitor a:hover { text-decoration: underline; }
    .ts { color: var(--muted); white-space: nowrap; font-size: 0.8rem; }
    .empty { color: var(--muted); padding: 3rem; text-align: center; }
    .expand { cursor: pointer; color: var(--accent); font-size: 0.8rem; user-select: none; }
    .btn-del { padding: 0.25rem 0.5rem; font-size: 0.75rem; background: transparent; color: var(--muted); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; text-decoration: none; }
    .btn-del:hover { color: #ef4444; border-color: #ef4444; }
    .btn-mass-del { font-size: 0.8rem; color: #ef4444; margin-left: 0.5rem; }
    .btn-mass-del:hover { text-decoration: underline; }
    .flash { background: var(--surface); border: 1px solid var(--green); color: var(--green); padding: 0.5rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem; }
    .expand:hover { text-decoration: underline; }
    .bulk-actions { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.75rem; margin: 0.75rem 0; padding: 0.75rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; font-size: 0.875rem; color: var(--muted); }
    .bulk-actions label { display: inline-flex; align-items: center; gap: 0.4rem; cursor: pointer; }
    .bulk-actions input[type=checkbox], .row-select { accent-color: var(--accent); cursor: pointer; }
    .bulk-actions .selected-count { color: var(--text); }
    .btn-bulk-del { padding: 0.4rem 0.75rem; background: #ef4444; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8125rem; }
    .btn-bulk-del:disabled { opacity: 0.45; cursor: not-allowed; }
    .btn-bulk-del:not(:disabled):hover { background: #dc2626; }
    th.select-col, td.select-col { width: 2.25rem; text-align: center; }
    .row-detail { display: none; background: var(--surface); }
    .row-detail.open { display: table-row; }
    .row-detail td { padding: 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    .detail-grid { display: grid; grid-template-columns: auto 1fr; gap: 0.5rem 1.5rem; font-size: 0.8rem; }
    .detail-grid dt { color: var(--muted); }
    .detail-grid dd { margin: 0; word-break: break-all; }
    .detail-block { margin-top: 1rem; }
    .detail-block h4 { font-size: 0.75rem; color: var(--muted); margin: 0 0 0.5rem; text-transform: uppercase; }
    pre { margin: 0; font-size: 0.7rem; background: var(--bg); padding: 0.75rem; border-radius: 6px; overflow-x: auto; max-height: 200px; overflow-y: auto; }
    .geo-section { margin-bottom: 1.5rem; }
    .geo-section h2 { font-size: 1rem; margin: 0 0 0.75rem; color: var(--muted); font-weight: 600; }
    .geo-toggle { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
    .geo-toggle label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.875rem; color: var(--muted); }
    .geo-toggle input { margin: 0; accent-color: var(--accent); }
    #geo-map { height: 380px; width: 100%; background: var(--surface); border-radius: 8px; border: 1px solid var(--border); }
    #geo-map.circles-clickable .leaflet-interactive { cursor: pointer; }
    .filters-section { margin: 1rem 0; padding: 1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; font-size: 0.875rem; }
    .filters-section h3 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 0.75rem; }
    .filters-row { display: flex; flex-wrap: wrap; gap: 1rem 1.5rem; align-items: flex-end; }
    .filter-group { display: flex; flex-direction: column; gap: 0.25rem; }
    .filter-group label { color: var(--muted); font-size: 0.75rem; }
    .filter-group input[type=text], .filter-group select { padding: 0.4rem 0.6rem; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 4px; font-size: 0.8125rem; min-width: 8rem; }
    .filter-group.hosts { flex-direction: row; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; }
    .filter-group.hosts .host-chks { display: flex; flex-wrap: wrap; gap: 0.35rem 0.75rem; align-items: center; }
    .filter-group.hosts label.inline { margin: 0; font-size: 0.8125rem; display: flex; align-items: center; gap: 0.35rem; cursor: pointer; }
    .filters-section button[type=submit] { padding: 0.4rem 0.75rem; background: var(--accent); color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8125rem; }
    .filters-section button[type=submit]:hover { background: #2563eb; }
    .filter-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: flex-end; align-self: flex-end; }
    .filters-section .btn-clear-filters {
      display: inline-flex; align-items: center; justify-content: center;
      padding: 0.4rem 0.75rem; background: transparent; color: var(--muted);
      border: 1px solid var(--border); border-radius: 4px; font-size: 0.8125rem;
      text-decoration: none; cursor: pointer; white-space: nowrap;
    }
    .filters-section .btn-clear-filters:hover { color: var(--text); border-color: var(--accent); }
    .hit-map-wrap { margin-top: 0.75rem; }
    .hit-map-wrap h4 { font-size: 0.75rem; color: var(--muted); margin: 0 0 0.5rem; text-transform: uppercase; }
    .hit-map-row { display: flex; flex-wrap: wrap; gap: 1rem; align-items: flex-start; }
    .hit-map-static { position: relative; height: 120px; width: 100%; max-width: 280px; min-width: 200px; background: var(--bg); border-radius: 6px; border: 1px solid var(--border); overflow: hidden; cursor: pointer; }
    .hit-map-static img { width: 100%; height: 100%; object-fit: cover; border-radius: 6px; display: block; }
    .hit-map-dot { position: absolute; width: 10px; height: 10px; background: var(--accent); border: 2px solid #fff; border-radius: 50%; transform: translate(-50%, -50%); pointer-events: none; }
    .hit-map-context { font-size: 0.8rem; color: var(--muted); line-height: 1.5; }
    .hit-map-context .coord { font-family: ui-monospace, monospace; color: var(--amber); }
    .hit-map-context .place { color: var(--green); margin-top: 0.35rem; }
    .host-badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; background: var(--surface); color: var(--muted); }
    .host-badge-primary { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }
    .pagination { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem 1rem; padding: 0.75rem 0; margin: 0.5rem 0; font-size: 0.875rem; color: var(--muted); }
    .pagination a { color: var(--accent); text-decoration: none; }
    .pagination a:hover { text-decoration: underline; }
    .pagination a.disabled { pointer-events: none; color: var(--border); cursor: default; }
    .pagination .page-info { margin-right: 0.5rem; }
    .pagination .page-jump { display: inline-flex; align-items: center; gap: 0.35rem; }
    .pagination .page-jump input { width: 3.5rem; padding: 0.35rem 0.5rem; font-size: 0.875rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); border-radius: 4px; text-align: center; }
    .pagination .per-page { display: inline-flex; align-items: center; gap: 0.35rem; margin-left: auto; }
    .pagination .per-page select { padding: 0.35rem 0.5rem; font-size: 0.875rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); border-radius: 4px; }
    @media (max-width: 760px) {
      .wrap { padding: 0.85rem; max-width: 100%; overflow-x: hidden; }
      header { align-items: stretch; gap: 0.75rem; margin-bottom: 1rem; }
      h1 { width: 100%; font-size: 1.15rem; }
      nav { width: 100%; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.5rem; }
      nav a, nav .badge { display: flex; align-items: center; justify-content: center; min-height: 2.5rem; padding: 0.55rem 0.65rem; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; text-align: center; margin: 0; }
      .btn-mass-del { color: #f87171; }
      .geo-section { margin-bottom: 1rem; }
      .geo-toggle { align-items: stretch; flex-direction: column; gap: 0.5rem; }
      .geo-toggle label { min-height: 2.5rem; padding: 0.55rem 0.65rem; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; }
      #geo-map { height: 300px; }
      .pagination { align-items: stretch; gap: 0.5rem; }
      .pagination .page-info { width: 100%; margin: 0; }
      .pagination a { min-height: 2.5rem; display: inline-flex; align-items: center; justify-content: center; padding: 0.5rem 0.75rem; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; flex: 1; }
      .pagination .page-jump, .pagination .per-page { width: 100%; margin-left: 0; justify-content: space-between; flex-wrap: wrap; }
      .pagination .page-jump input, .pagination .page-jump button, .pagination .per-page select { min-height: 2.5rem; }
      .filters-section { padding: 0.85rem; }
      .filters-row { display: grid; grid-template-columns: 1fr; gap: 0.8rem; }
      .filter-group, .filter-group.hosts { width: 100%; align-items: stretch; }
      .filter-group input[type=text], .filter-group select { width: 100%; min-width: 0; min-height: 2.5rem; font-size: 1rem; }
      .filter-group.hosts .host-chks { align-items: stretch; flex-direction: column; }
      .filter-group.hosts label.inline { min-height: 2.25rem; }
      .filters-section button[type=submit], .filters-section .btn-clear-filters, .btn-bulk-del { width: 100%; min-height: 2.5rem; }
      .filter-actions { width: 100%; flex-direction: column; }
      .bulk-actions { align-items: stretch; flex-direction: column; }
      .bulk-actions label { min-height: 2.5rem; }
      #hits-table { display: block; width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
      #hits-table th, #hits-table td { padding: 0.65rem 0.7rem; }
      #hits-table th { white-space: nowrap; }
      #hits-table .path { max-width: 12rem; }
      .row-detail td { padding: 0.8rem; }
      .detail-grid { grid-template-columns: 1fr; gap: 0.2rem 0; }
      .detail-grid dt { margin-top: 0.4rem; }
      .hit-map-row { flex-direction: column; }
      .hit-map-static { max-width: none; min-width: 0; }
      pre { max-width: calc(100vw - 3.4rem); }
    }
    @media (max-width: 420px) {
      nav { grid-template-columns: 1fr; }
      #geo-map { height: 260px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    {% if deleted is not none and deleted > 0 %}
    <p class="flash">{{ deleted }} log(s) deleted.</p>
    {% endif %}
    <header>
      <h1>Honeytoken Admin</h1>
      <nav>
        <a href="/">Hits</a>
        <a href="/links">Links</a>
        <a href="/settings">Settings</a>
        <a href="/nginx">Nginx config</a>
        <span class="badge">{{ count }} hits</span>
        <a href="/delete-all" class="btn-mass-del">Delete all logs</a>
      </nav>
    </header>
    <section class="geo-section">
      <h2>Geographic Heatmap</h2>
      <div class="geo-toggle">
        <label><input type="radio" name="geo-mode" value="heat"> Heatmap (density)</label>
        <label><input type="radio" name="geo-mode" value="circles" checked> Marker / Circle</label>
      </div>
      <div id="geo-map"></div>
    </section>
    {% if total_pages >= 1 %}
    <nav class="pagination" aria-label="Hits pagination">
      <span class="page-info">Page {{ page }} of {{ total_pages }}</span>
      <a href="?page={{ page - 1 }}&per_page={{ per_page }}{{ filter_query_string }}" class="{{ 'disabled' if page <= 1 else '' }}" aria-label="Previous page">Prev</a>
      <a href="?page={{ page + 1 }}&per_page={{ per_page }}{{ filter_query_string }}" class="{{ 'disabled' if page >= total_pages else '' }}" aria-label="Next page">Next</a>
      <form method="get" action="" class="page-jump" style="display:inline-flex; align-items:center; gap:0.35rem;">
        <input type="hidden" name="per_page" value="{{ per_page }}">
        {% if filter_gpu %}<input type="hidden" name="gpu" value="{{ filter_gpu }}">{% endif %}
        {% if filter_fingerprint %}<input type="hidden" name="fingerprint" value="{{ filter_fingerprint }}">{% endif %}
        {% if filter_visitor_fp %}<input type="hidden" name="visitor_fp" value="{{ filter_visitor_fp }}">{% endif %}
        {% if filter_repeat %}<input type="hidden" name="repeat" value="{{ filter_repeat }}">{% endif %}
        {% if filter_location %}<input type="hidden" name="location" value="{{ filter_location }}">{% endif %}
        {% if filter_path %}<input type="hidden" name="path" value="{{ filter_path }}">{% endif %}
        {% for h in filter_hosts %}<input type="hidden" name="host" value="{{ h }}">{% endfor %}
        {% if filter_link %}<input type="hidden" name="link" value="{{ filter_link }}">{% endif %}
        <label for="page-num-top">Jump to page</label>
        <input type="number" id="page-num-top" name="page" min="1" max="{{ total_pages }}" value="{{ page }}" aria-label="Page number" style="width:3.5rem;padding:0.35rem 0.5rem;font-size:0.875rem;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:4px;text-align:center;">
        <button type="submit">Go</button>
      </form>
      <form method="get" action="" class="per-page">
        <input type="hidden" name="page" value="1">
        {% if filter_gpu %}<input type="hidden" name="gpu" value="{{ filter_gpu }}">{% endif %}
        {% if filter_fingerprint %}<input type="hidden" name="fingerprint" value="{{ filter_fingerprint }}">{% endif %}
        {% if filter_visitor_fp %}<input type="hidden" name="visitor_fp" value="{{ filter_visitor_fp }}">{% endif %}
        {% if filter_repeat %}<input type="hidden" name="repeat" value="{{ filter_repeat }}">{% endif %}
        {% if filter_location %}<input type="hidden" name="location" value="{{ filter_location }}">{% endif %}
        {% if filter_path %}<input type="hidden" name="path" value="{{ filter_path }}">{% endif %}
        {% for h in filter_hosts %}<input type="hidden" name="host" value="{{ h }}">{% endfor %}
        {% if filter_link %}<input type="hidden" name="link" value="{{ filter_link }}">{% endif %}
        <label for="per-page-top">Per page</label>
        <select name="per_page" id="per-page-top" onchange="this.form.submit()" aria-label="Results per page">
          {% for n in per_page_options %}
          <option value="{{ n }}" {{ 'selected' if n == per_page else '' }}>{{ n }}</option>
          {% endfor %}
        </select>
      </form>
    </nav>
    {% endif %}
    <section class="filters-section" aria-label="Filter hits">
      <h3>Filters</h3>
      <form method="get" action="" id="filters-form">
        <input type="hidden" name="page" value="1">
        <input type="hidden" name="per_page" value="{{ per_page }}">
        <div class="filters-row">
          <div class="filter-group">
            <label for="filter-gpu">GPU detected</label>
            <select id="filter-gpu" name="gpu">
              <option value="">Any</option>
              <option value="yes" {{ 'selected' if filter_gpu == 'yes' else '' }}>Yes</option>
              <option value="no" {{ 'selected' if filter_gpu == 'no' else '' }}>No</option>
            </select>
          </div>
          <div class="filter-group">
            <label for="filter-fingerprint">Fingerprint detected</label>
            <select id="filter-fingerprint" name="fingerprint">
              <option value="">Any</option>
              <option value="yes" {{ 'selected' if filter_fingerprint == 'yes' else '' }}>Yes</option>
              <option value="no" {{ 'selected' if filter_fingerprint == 'no' else '' }}>No</option>
            </select>
          </div>
          <div class="filter-group">
            <label for="filter-visitor-fp">Visitor fingerprint</label>
            <input type="text" id="filter-visitor-fp" name="visitor_fp" value="{{ filter_visitor_fp }}" placeholder="12+ hex chars" maxlength="64" style="font-family:ui-monospace,monospace;">
          </div>
          <div class="filter-group">
            <label for="filter-repeat">Repeat visitor</label>
            <select id="filter-repeat" name="repeat">
              <option value="">Any</option>
              <option value="yes" {{ 'selected' if filter_repeat == 'yes' else '' }}>Yes only</option>
            </select>
          </div>
          <div class="filter-group">
            <label for="filter-location">Location contains</label>
            <input type="text" id="filter-location" name="location" value="{{ filter_location }}" placeholder="e.g. United States" maxlength="200">
          </div>
          <div class="filter-group">
            <label for="filter-path">Path contains</label>
            <input type="text" id="filter-path" name="path" value="{{ filter_path }}" placeholder="e.g. .env" maxlength="200">
          </div>
          <div class="filter-group">
            <label for="filter-link">Generated link</label>
            <select id="filter-link" name="link">
              <option value="">Any</option>
              {% for link in tracked_links %}
              <option value="{{ link.get('_id') }}" {{ 'selected' if filter_link == (link.get('_id')|string) else '' }}>{{ link.get('label') or link.get('token') }}</option>
              {% endfor %}
            </select>
          </div>
          <div class="filter-group hosts">
            <span style="color: var(--muted); font-size: 0.75rem;">Host</span>
            <div class="host-chks">
              {% for h in distinct_hosts %}
              <label class="inline"><input type="checkbox" name="host" value="{{ h }}" {{ 'checked' if h in filter_hosts else '' }}> {{ h }}</label>
              {% endfor %}
              {% if not distinct_hosts %}<span style="color: var(--muted);">No hosts in data</span>{% endif %}
            </div>
          </div>
          <div class="filter-actions">
            <button type="submit">Apply filters</button>
            <a class="btn-clear-filters" href="/?page=1&amp;per_page={{ per_page }}" aria-label="Clear all filters">Clear filters</a>
          </div>
        </div>
      </form>
    </section>
    {% if hits %}
    <form method="post" action="/hits/delete" id="bulk-delete-form">
      <input type="hidden" name="return_page" value="{{ page }}">
      <input type="hidden" name="return_per_page" value="{{ per_page }}">
      {% if filter_gpu %}<input type="hidden" name="return_gpu" value="{{ filter_gpu }}">{% endif %}
      {% if filter_fingerprint %}<input type="hidden" name="return_fingerprint" value="{{ filter_fingerprint }}">{% endif %}
      {% if filter_visitor_fp %}<input type="hidden" name="return_visitor_fp" value="{{ filter_visitor_fp }}">{% endif %}
      {% if filter_repeat %}<input type="hidden" name="return_repeat" value="{{ filter_repeat }}">{% endif %}
      {% if filter_location %}<input type="hidden" name="return_location" value="{{ filter_location }}">{% endif %}
      {% if filter_path %}<input type="hidden" name="return_path" value="{{ filter_path }}">{% endif %}
      {% for host in filter_hosts %}<input type="hidden" name="return_host" value="{{ host }}">{% endfor %}
      {% if filter_link %}<input type="hidden" name="return_link" value="{{ filter_link }}">{% endif %}
    </form>
    <div class="bulk-actions" aria-label="Bulk hit actions">
      <label><input type="checkbox" class="select-page" aria-label="Select all hits on this page"> Select page</label>
      <span><span class="selected-count">0</span> selected</span>
      <button type="submit" form="bulk-delete-form" class="btn-bulk-del" disabled>Delete selected</button>
    </div>
    <table id="hits-table">
      <thead>
        <tr>
          <th class="select-col"></th>
          <th title="{{ timezone }}">Time</th>
          <th>Host</th>
          <th>IP</th>
          <th>Location</th>
          <th>Path</th>
          <th>Link</th>
          <th>GPU</th>
          <th>Visitor</th>
        </tr>
      </thead>
      <tbody>
        {% for h in hits %}
        <tr class="data-row" data-id="{{ h.get('_id') }}">
          <td class="select-col"><input type="checkbox" class="row-select" name="hit_id" value="{{ h.get('_id') }}" form="bulk-delete-form" aria-label="Select hit {{ h.get('_id') }}"></td>
          <td class="ts" title="{{ timezone }}">{{ format_ts_readable(h.get('_ts'), timezone) }}</td>
          <td>{% set hd = host_display(h) %}<span class="{{ hd[1] }}" title="{{ hd[0] }}">{{ hd[0] }}</span></td>
          <td class="ip">{{ h.get('ip', '') }}</td>
          <td class="location">{{ location_str(h) }}</td>
          <td class="path" title="{{ h.get('path', '') }}">{{ h.get('path', '') }}</td>
          <td>{% set link = tracked_links_by_id.get(h.get('link_id')) %}{% if link %}<a href="/links/{{ link.get('_id') }}">{{ link.get('label') or link.get('token') }}</a>{% else %}—{% endif %}</td>
          <td class="gpu" title="{{ gpu_str(h) }}">{{ gpu_str(h) }}</td>
          <td class="visitor">{% set vd = visitor_display(h) %}{% if vd[1] %}<a href="/?visitor_fp={{ vd[1] }}&sort_visitor=1" title="{{ vd[1] }}">{{ vd[0] }}</a>{% else %}—{% endif %}</td>
        </tr>
        <tr class="row-detail" id="detail-{{ h.get('_id') }}">
          <td colspan="10">
            <div class="detail-grid">
              <dt>Time (UTC)</dt><dd>{{ h.get('_ts', '') or '—' }}</dd>
              <dt>Time ({{ timezone }})</dt><dd>{{ format_ts_readable(h.get('_ts'), timezone) }}</dd>
              <dt>Host</dt><dd>{% set hd = host_display(h) %}<span class="{{ hd[1] }}">{{ hd[0] }}</span></dd>
              <dt>Generated link</dt><dd>{% set link = tracked_links_by_id.get(h.get('link_id')) %}{% if link %}<a href="/links/{{ link.get('_id') }}">{{ link.get('label') or link.get('token') }}</a>{% else %}—{% endif %}</dd>
              <dt>Method</dt><dd>{{ h.get('method', '') }}</dd>
              <dt>OS</dt><dd>{{ (h.get('fingerprint') or {}).get('os_guess', '—') }}</dd>
              <dt>Browser</dt><dd>{{ (h.get('fingerprint') or {}).get('browser_guess', '—') }}</dd>
              <dt>Locale</dt><dd>{{ (h.get('fingerprint') or {}).get('locale_guess', '—') }}</dd>
              <dt>User-Agent</dt><dd style="word-break:break-all;">{{ (h.get('fingerprint') or {}).get('user_agent_raw', '—') }}</dd>
              {% set vd = visitor_display(h) %}
              <dt>Visitor fingerprint</dt><dd>{% if vd[1] %}<a href="/?visitor_fp={{ vd[1] }}&sort_visitor=1">{{ vd[1] }}</a>{% else %}—{% endif %}</dd>
              {% if vd[2] %}
              <dt>Visit # (global)</dt><dd>{{ vd[2].get('global_visit_number', '—') }}{% if vd[2].get('is_repeat') %} (repeat){% endif %}</dd>
              {% if vd[2].get('link_visit_number') is not none %}
              <dt>Visit # (this link)</dt><dd>{{ vd[2].get('link_visit_number') }}{% if vd[2].get('is_repeat_link') %} (repeat on link){% endif %}</dd>
              {% endif %}
              {% endif %}
              {% if h.get('location') %}
              <dt>ISP</dt><dd>{{ (h.get('location') or {}).get('isp', '—') }}</dd>
              {% endif %}
            </div>
            {% if h.get('latitude') is not none and h.get('longitude') is not none %}
            <div class="detail-block hit-map-wrap">
              <h4>Location</h4>
              <div class="hit-map-row">
                <div class="hit-map-static hit-map" data-lat="{{ h.get('latitude') }}" data-lng="{{ h.get('longitude') }}" data-inited="0" title="Click to zoom main map to this location"></div>
                <div class="hit-map-context">
                  <div class="coord">{{ "%.6f"|format(h.get('latitude')) }}, {{ "%.6f"|format(h.get('longitude')) }}</div>
                  <div class="place">{{ location_str(h) if location_str(h) != '—' else 'Approximate location (no city data)' }}</div>
                </div>
              </div>
            </div>
            {% endif %}
            {% if h.get('client_fingerprint') %}
            <div class="detail-block">
              <h4>Client fingerprint</h4>
              <pre>{{ (h.get('client_fingerprint') or {}) | tojson(indent=2) }}</pre>
            </div>
            {% endif %}
            <div class="detail-block">
              <h4>Request headers</h4>
              <pre>{{ (h.get('headers') or {}) | tojson(indent=2) }}</pre>
            </div>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div class="bulk-actions" aria-label="Bulk hit actions">
      <label><input type="checkbox" class="select-page" aria-label="Select all hits on this page"> Select page</label>
      <span><span class="selected-count">0</span> selected</span>
      <button type="submit" form="bulk-delete-form" class="btn-bulk-del" disabled>Delete selected</button>
    </div>
    {% if total_pages >= 1 %}
    <nav class="pagination" aria-label="Hits pagination">
      <span class="page-info">Page {{ page }} of {{ total_pages }}</span>
      <a href="?page={{ page - 1 }}&per_page={{ per_page }}{{ filter_query_string }}" class="{{ 'disabled' if page <= 1 else '' }}" aria-label="Previous page">Prev</a>
      <a href="?page={{ page + 1 }}&per_page={{ per_page }}{{ filter_query_string }}" class="{{ 'disabled' if page >= total_pages else '' }}" aria-label="Next page">Next</a>
      <form method="get" action="" class="page-jump" style="display:inline-flex; align-items:center; gap:0.35rem;">
        <input type="hidden" name="per_page" value="{{ per_page }}">
        {% if filter_gpu %}<input type="hidden" name="gpu" value="{{ filter_gpu }}">{% endif %}
        {% if filter_fingerprint %}<input type="hidden" name="fingerprint" value="{{ filter_fingerprint }}">{% endif %}
        {% if filter_visitor_fp %}<input type="hidden" name="visitor_fp" value="{{ filter_visitor_fp }}">{% endif %}
        {% if filter_repeat %}<input type="hidden" name="repeat" value="{{ filter_repeat }}">{% endif %}
        {% if filter_location %}<input type="hidden" name="location" value="{{ filter_location }}">{% endif %}
        {% if filter_path %}<input type="hidden" name="path" value="{{ filter_path }}">{% endif %}
        {% for h in filter_hosts %}<input type="hidden" name="host" value="{{ h }}">{% endfor %}
        {% if filter_link %}<input type="hidden" name="link" value="{{ filter_link }}">{% endif %}
        <label for="page-num-bottom">Jump to page</label>
        <input type="number" id="page-num-bottom" name="page" min="1" max="{{ total_pages }}" value="{{ page }}" aria-label="Page number" style="width:3.5rem;padding:0.35rem 0.5rem;font-size:0.875rem;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:4px;text-align:center;">
        <button type="submit">Go</button>
      </form>
      <form method="get" action="" class="per-page">
        <input type="hidden" name="page" value="1">
        {% if filter_gpu %}<input type="hidden" name="gpu" value="{{ filter_gpu }}">{% endif %}
        {% if filter_fingerprint %}<input type="hidden" name="fingerprint" value="{{ filter_fingerprint }}">{% endif %}
        {% if filter_visitor_fp %}<input type="hidden" name="visitor_fp" value="{{ filter_visitor_fp }}">{% endif %}
        {% if filter_repeat %}<input type="hidden" name="repeat" value="{{ filter_repeat }}">{% endif %}
        {% if filter_location %}<input type="hidden" name="location" value="{{ filter_location }}">{% endif %}
        {% if filter_path %}<input type="hidden" name="path" value="{{ filter_path }}">{% endif %}
        {% for h in filter_hosts %}<input type="hidden" name="host" value="{{ h }}">{% endfor %}
        {% if filter_link %}<input type="hidden" name="link" value="{{ filter_link }}">{% endif %}
        <label for="per-page-bottom">Per page</label>
        <select name="per_page" id="per-page-bottom" onchange="this.form.submit()" aria-label="Results per page">
          {% for n in per_page_options %}
          <option value="{{ n }}" {{ 'selected' if n == per_page else '' }}>{{ n }}</option>
          {% endfor %}
        </select>
      </form>
    </nav>
    {% endif %}
    {% else %}
    <p class="empty">No hits yet.</p>
    {% endif %}
  </div>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
  <script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js" crossorigin=""></script>
  <script>
    (function() {
      var CARTODB_DARK = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
      var geoPoints = {{ page_geo_points | tojson }};
      /** Group hits that share ~same GeoIP cell so circles do not pile up as one giant overlapping blob. */
      function aggregateGeoForMap(points, decimals) {
        decimals = typeof decimals === 'number' ? decimals : 4;
        var factor = Math.pow(10, decimals);
        var m = {};
        points.forEach(function(p) {
          var lat = Number(p.lat);
          var lng = Number(p.lng);
          if (isNaN(lat) || isNaN(lng)) return;
          var key = Math.round(lat * factor) / factor + '_' + (Math.round(lng * factor) / factor);
          if (!m[key]) {
            m[key] = { lat: lat, lng: lng, weight: 0, hit_ids: [] };
          }
          m[key].weight += Number(p.weight) > 0 ? Number(p.weight) : 1;
          if (p.hit_id != null) m[key].hit_ids.push(p.hit_id);
        });
        return Object.keys(m).map(function(k) { return m[k]; });
      }
      var geoAgg = aggregateGeoForMap(geoPoints);
      var mainMap = null;
      var heatLayer = null;
      var circleLayer = null;
      var currentMode = 'circles';
      var geoMapEl = document.getElementById('geo-map');

      function initMainMap() {
        if (mainMap) return;
        mainMap = L.map('geo-map', { attributionControl: false }).setView([20, 0], 2);
        L.tileLayer(CARTODB_DARK, { subdomains: 'abcd', maxZoom: 19 }).addTo(mainMap);
      }

      function latLngToTile(lat, lng, zoom) {
        var n = Math.pow(2, zoom);
        var x = Math.floor((lng + 180) / 360 * n);
        var rad = lat * Math.PI / 180;
        var y = Math.floor((1 - Math.log(Math.tan(rad) + 1 / Math.cos(rad)) / Math.PI) / 2 * n);
        return { x: x, y: y, z: zoom };
      }

      function scrollToHitAndExpand(hitId) {
        var id = String(hitId);
        var table = document.getElementById('hits-table');
        if (!table) return;
        var dataRow = table.querySelector('.data-row[data-id="' + id + '"]');
        if (!dataRow) return;
        dataRow.scrollIntoView({ behavior: 'smooth', block: 'start', inline: 'nearest' });
        requestAnimationFrame(function() {
          requestAnimationFrame(function() {
            toggleDetail(id, true);
          });
        });
      }

      function renderGeoView() {
        if (!mainMap) return;
        if (heatLayer) { mainMap.removeLayer(heatLayer); heatLayer = null; }
        if (circleLayer) {
          mainMap.removeLayer(circleLayer);
          circleLayer = null;
        }
        if (geoMapEl) geoMapEl.classList.remove('circles-clickable');
        if (!geoPoints.length) return;
        if (currentMode === 'heat') {
          var heatData = geoAgg.map(function(p) {
            var w = Number(p.weight) || 1;
            return [p.lat, p.lng, Math.max(0.12, w)];
          });
          heatLayer = L.heatLayer(heatData, {
            radius: 28,
            blur: 18,
            maxZoom: 16,
            gradient: { 0.2: '#3b82f6', 0.5: '#f59e0b', 0.9: '#ef4444', 1: '#7c2d12' }
          });
          mainMap.addLayer(heatLayer);
        } else {
          if (geoMapEl) geoMapEl.classList.add('circles-clickable');
          circleLayer = L.layerGroup();
          var maxW = Math.max.apply(null, geoAgg.map(function(p) { return p.weight; })) || 1;
          geoAgg.forEach(function(p) {
            var n = Number(p.weight) || 1;
            var norm = Math.sqrt(n / maxW);
            /** Pixel radius: stays readable at any zoom (unlike meter-based circles that covered whole cities). */
            var rPx = Math.round(Math.min(34, Math.max(6, 7 + 20 * norm)));
            var marker = L.circleMarker([p.lat, p.lng], {
              radius: rPx,
              color: '#93c5fd',
              fillColor: '#3b82f6',
              fillOpacity: Math.min(0.65, 0.35 + 0.08 * Math.min(n, 6)),
              weight: Math.min(4, n >= 10 ? 3 : (n >= 4 ? 2 : 1))
            });
            if (p.hit_ids && p.hit_ids.length > 1) {
              marker.bindTooltip(String(n) + ' hits · same map cell', { direction: 'top', sticky: true, opacity: 0.92 });
              marker.on('click', function() { scrollToHitAndExpand(p.hit_ids[0]); });
            } else if (p.hit_ids && p.hit_ids.length === 1) {
              marker.bindTooltip('Hit #' + String(p.hit_ids[0]), { direction: 'top', sticky: true, opacity: 0.9 });
              marker.on('click', function() { scrollToHitAndExpand(p.hit_ids[0]); });
            }
            marker.addTo(circleLayer);
          });
          mainMap.addLayer(circleLayer);
        }
      }

      initMainMap();
      if (geoPoints.length) {
        var bounds = L.latLngBounds(geoPoints.map(function(p) { return [p.lat, p.lng]; }));
        var ne = bounds.getNorthEast();
        var sw = bounds.getSouthWest();
        var diagonalMeters = bounds.isValid() ? ne.distanceTo(sw) : 0;
        if (!bounds.isValid() || diagonalMeters < 80) {
          var sumLat = 0;
          var sumLng = 0;
          geoPoints.forEach(function(p) { sumLat += p.lat; sumLng += p.lng; });
          var inv = geoPoints.length ? 1 / geoPoints.length : 1;
          mainMap.setView([sumLat * inv, sumLng * inv], 11);
        } else {
          mainMap.fitBounds(bounds, { padding: [28, 28], maxZoom: 14 });
        }
      }
      renderGeoView();

      document.querySelectorAll('input[name=geo-mode]').forEach(function(radio) {
        radio.addEventListener('change', function() {
          currentMode = this.value;
          renderGeoView();
        });
      });

      function initHitMap(row) {
        var hitMap = row ? row.querySelector('.hit-map') : null;
        if (!hitMap || hitMap.getAttribute('data-inited') === '1') return;
        var lat = parseFloat(hitMap.getAttribute('data-lat'));
        var lng = parseFloat(hitMap.getAttribute('data-lng'));
        if (isNaN(lat) || isNaN(lng)) return;
        var zoom = 14;
        var t = latLngToTile(lat, lng, zoom);
        var url = CARTODB_DARK.replace('{s}', 'a').replace('{z}', t.z).replace('{x}', t.x).replace('{y}', t.y).replace('{r}', '');
        var n = Math.pow(2, zoom);
        var latRad = lat * Math.PI / 180;
        var latY = (1 - Math.log(Math.tan(latRad) + 1 / Math.cos(latRad)) / Math.PI) / 2 * n;
        var px = ((lng + 180) / 360 * n - t.x) * 256;
        var py = (latY - t.y) * 256;
        var img = document.createElement('img');
        img.src = url;
        img.alt = 'Location';
        img.loading = 'lazy';
        hitMap.appendChild(img);
        var dot = document.createElement('div');
        dot.className = 'hit-map-dot';
        dot.style.left = (px / 256 * 100) + '%';
        dot.style.top = (py / 256 * 100) + '%';
        hitMap.appendChild(dot);
        hitMap.setAttribute('data-inited', '1');
      }

      function toggleDetail(id, forceOpen) {
        var row = document.getElementById('detail-' + id);
        if (!row) return;
        if (typeof forceOpen === 'boolean') {
          row.classList.toggle('open', forceOpen);
        } else {
          row.classList.toggle('open');
        }
        if (row.classList.contains('open')) initHitMap(row);
      }

      document.querySelectorAll('.data-row').forEach(function(row) {
        row.addEventListener('click', function(e) {
          if (e.target.closest('a, button, input, select, textarea, label, form, .hit-map, .select-col')) return;
          toggleDetail(row.getAttribute('data-id'));
        });
      });

      var bulkForm = document.getElementById('bulk-delete-form');
      var rowSelects = Array.prototype.slice.call(document.querySelectorAll('.row-select'));
      var selectPageBoxes = Array.prototype.slice.call(document.querySelectorAll('.select-page'));
      var selectedCounts = Array.prototype.slice.call(document.querySelectorAll('.selected-count'));
      var bulkDeleteButtons = Array.prototype.slice.call(document.querySelectorAll('.btn-bulk-del'));

      function updateBulkState() {
        var selected = rowSelects.filter(function(cb) { return cb.checked; });
        selectedCounts.forEach(function(el) { el.textContent = String(selected.length); });
        bulkDeleteButtons.forEach(function(btn) { btn.disabled = selected.length === 0; });
        selectPageBoxes.forEach(function(cb) {
          cb.checked = rowSelects.length > 0 && selected.length === rowSelects.length;
          cb.indeterminate = selected.length > 0 && selected.length < rowSelects.length;
        });
        rowSelects.forEach(function(cb) {
          var row = cb.closest('.data-row');
          if (row) row.classList.toggle('selected', cb.checked);
        });
      }

      rowSelects.forEach(function(cb) {
        cb.addEventListener('change', updateBulkState);
        cb.addEventListener('click', function(e) { e.stopPropagation(); });
      });
      selectPageBoxes.forEach(function(cb) {
        cb.addEventListener('change', function() {
          rowSelects.forEach(function(rowCb) { rowCb.checked = cb.checked; });
          updateBulkState();
        });
      });
      if (bulkForm) {
        bulkForm.addEventListener('submit', function(e) {
          var selected = rowSelects.filter(function(cb) { return cb.checked; }).length;
          if (!selected) {
            e.preventDefault();
            return;
          }
          if (!confirm('Delete ' + selected + ' selected hit(s)?')) e.preventDefault();
        });
      }
      updateBulkState();
      document.addEventListener('click', function(e) {
        var el = e.target.closest('.hit-map');
        if (!el || !mainMap) return;
        var lat = parseFloat(el.getAttribute('data-lat'));
        var lng = parseFloat(el.getAttribute('data-lng'));
        if (isNaN(lat) || isNaN(lng)) return;
        mainMap.flyTo([lat, lng], 14, { duration: 0.5 });
      });
    })();
  </script>
</body>
</html>
"""


DELETE_ALL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Delete all logs – Honeytoken Admin</title>
  <style>
    :root { --bg: #0a0a0b; --surface: #141416; --border: #27272a; --muted: #71717a; --text: #fafafa; --accent: #3b82f6; --red: #ef4444; }
    * { box-sizing: border-box; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); min-height: 100vh; }
    .wrap { max-width: 28rem; margin: 0 auto; padding: 1.5rem; }
    h1 { font-size: 1.25rem; margin-bottom: 0.5rem; }
    .meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .warn { background: rgba(239,68,68,0.1); border: 1px solid var(--red); border-radius: 8px; padding: 1rem; margin: 1rem 0; font-size: 0.875rem; color: #fca5a5; }
    label { display: block; margin-top: 1rem; color: var(--muted); font-size: 0.875rem; }
    input[type=text] { width: 100%; padding: 0.5rem 0.75rem; margin-top: 0.25rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); border-radius: 6px; font-size: 0.875rem; }
    .btn { margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.875rem; cursor: pointer; border: none; }
    .btn-danger { background: var(--red); color: #fff; }
    .btn-danger:hover { background: #dc2626; }
    .btn-danger:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-cancel { background: var(--surface); color: var(--muted); margin-left: 0.5rem; text-decoration: none; display: inline-block; }
    .btn-cancel:hover { color: var(--text); }
    @media (max-width: 520px) {
      .wrap { max-width: 100%; padding: 0.85rem; }
      h1 { font-size: 1.15rem; }
      input[type=text], .btn { width: 100%; min-height: 2.5rem; font-size: 1rem; }
      .btn-cancel { margin-left: 0; text-align: center; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Delete all logs</h1>
    <p class="meta"><a href="/">← Dashboard</a> · <a href="/links">Links</a></p>
    <div class="warn">
      <strong>This cannot be undone.</strong> All {{ count }} hit logs will be permanently deleted. This action is irreversible.
    </div>
    <p style="color: var(--muted); font-size: 0.875rem;">To confirm, type <strong>DELETE ALL</strong> below and click Delete.</p>
    <form method="post" action="/delete-all" id="del-form">
      <input type="hidden" name="confirm" value="">
      <label for="confirm_input">Confirmation</label>
      <input type="text" id="confirm_input" name="confirm_input" value="" placeholder="Type DELETE ALL" autocomplete="off">
      <button type="submit" class="btn btn-danger" id="del-btn" disabled>Delete all {{ count }} logs</button>
      <a href="/" class="btn btn-cancel">Cancel</a>
    </form>
  </div>
  <script>
    var input = document.getElementById('confirm_input');
    var btn = document.getElementById('del-btn');
    var form = document.getElementById('del-form');
    input.addEventListener('input', function() {
      btn.disabled = input.value.trim() !== 'DELETE ALL';
    });
    form.addEventListener('submit', function(e) {
      if (input.value.trim() !== 'DELETE ALL') { e.preventDefault(); return; }
      document.querySelector('input[name=confirm]').value = input.value.trim();
    });
  </script>
</body>
</html>
"""


LINKS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Links - Honeytoken Admin</title>
  <style>
    :root { --bg: #0a0a0b; --surface: #141416; --border: #27272a; --muted: #71717a; --text: #fafafa; --accent: #3b82f6; --green: #22c55e; --amber: #f59e0b; --red: #ef4444; }
    * { box-sizing: border-box; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--text); min-height: 100vh; }
    .wrap { max-width: 72rem; margin: 0 auto; padding: 1.5rem; }
    header { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 1rem; align-items: center; margin-bottom: 1.5rem; }
    h1 { font-size: 1.4rem; margin: 0; }
    h2 { font-size: 1rem; margin: 0 0 0.75rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    nav { display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; font-size: 0.875rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; margin-bottom: 1rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: 0.75rem 1rem; }
    label { display: block; color: var(--muted); font-size: 0.8rem; margin-bottom: 0.25rem; }
    input[type=text], input[type=number], select, textarea { width: 100%; padding: 0.5rem 0.65rem; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; font-size: 0.875rem; }
    textarea { resize: vertical; font-family: inherit; }
    button, .btn { display: inline-block; padding: 0.5rem 0.85rem; background: var(--accent); color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.875rem; text-decoration: none; }
    button:hover, .btn:hover { background: #2563eb; text-decoration: none; }
    .muted { color: var(--muted); font-size: 0.85rem; }
    .mode-toggles { display: flex; gap: 0; margin: 0.75rem 0; background: var(--bg); border-radius: 8px; padding: 4px; border: 1px solid var(--border); max-width: 28rem; }
    .mode-btn { flex: 1; background: transparent; color: var(--muted); }
    .mode-btn.active { background: var(--accent); color: #fff; }
    .panel { display: none; }
    .panel.active { display: block; }
    .created { border-color: rgba(34,197,94,0.4); }
    .created input { font-family: ui-monospace, monospace; color: var(--green); }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    table:not(.links-stats-table) th, table:not(.links-stats-table) td {
      padding: 0.65rem 0.5rem;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }
    table:not(.links-stats-table) th { color: var(--muted); font-weight: 600; }
    .links-stats-table th, .links-stats-table td {
      padding: 0.72rem 0.6rem;
      text-align: left;
      vertical-align: middle;
      border-bottom: none;
    }
    .links-stats-table thead th {
      color: var(--muted);
      font-weight: 600;
      vertical-align: bottom;
      padding-bottom: 0.55rem;
      border-bottom: 1px solid var(--border);
    }
    .links-stats-table tbody tr + tr td {
      border-top: 1px solid var(--border);
    }
    .links-stats-table tbody td.link-cell { vertical-align: top; padding-top: 0.72rem; }
    .links-stats-table tbody td.cell-actions {
      vertical-align: middle;
      white-space: nowrap;
    }
    .token { font-family: ui-monospace, monospace; color: var(--amber); }
    .inactive td { opacity: 0.85; }
    .inactive .token { color: var(--muted); }
    .link-cell .link-meta { display: flex; flex-direction: column; gap: 0.35rem; }
    .link-cell .link-dest-muted { color: var(--muted); font-size: 0.8rem; line-height: 1.35; word-break: break-word; max-width: 36rem; }
    .link-url-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.4rem 0.65rem; }
    .link-url-row .full-url-anchor { font-family: ui-monospace, monospace; font-size: 0.8125rem; color: var(--green); overflow-wrap: anywhere; }
    button.btn-copy-mini {
      flex-shrink: 0;
      font-size: 0.75rem;
      padding: 0.28rem 0.55rem;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 5px;
      cursor: pointer;
      font-family: inherit;
      line-height: 1.2;
      min-height: 0;
    }
    button.btn-copy-mini:hover { border-color: var(--accent); color: var(--accent); background: var(--surface); }
    button.btn-copy-mini.copied { border-color: var(--green); color: var(--green); }
    .link-path-kind { margin: 0.2rem 0 0; font-size: 0.72rem; color: var(--muted); max-width: 38rem; line-height: 1.35; }
    .cell-actions { display: inline-flex; flex-wrap: wrap; gap: 0.5rem 0.85rem; align-items: center; }
    .cell-actions a.action-link {
      color: var(--accent);
      text-decoration: none;
      font-weight: 500;
      padding: 0.12rem 0;
    }
    .cell-actions a.action-link:hover { text-decoration: underline; }
    .url-preview { margin-top: 0.5rem; padding: 0.65rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; }
    .url-preview code { display: block; color: var(--green); font-family: ui-monospace, monospace; overflow-wrap: anywhere; }
    .url-preview.warning code { color: var(--amber); }
    .url-preview.error code { color: var(--red); }
    @media (max-width: 760px) {
      .wrap { max-width: 100%; padding: 0.85rem; overflow-x: hidden; }
      header { align-items: stretch; gap: 0.75rem; margin-bottom: 1rem; }
      h1 { width: 100%; font-size: 1.15rem; }
      nav { width: 100%; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.5rem; }
      nav a { display: flex; align-items: center; justify-content: center; min-height: 2.5rem; padding: 0.55rem 0.65rem; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; text-align: center; }
      .card { padding: 0.85rem; border-radius: 8px; }
      .grid { grid-template-columns: 1fr; gap: 0.75rem; }
      input[type=text], input[type=number], select, textarea, button, .btn { min-height: 2.5rem; font-size: 1rem; }
      button.btn-copy-mini { min-height: 0; font-size: 0.75rem; padding: 0.35rem 0.55rem; }
      .mode-toggles { max-width: none; }
      .mode-btn { min-height: 2.4rem; padding-left: 0.4rem; padding-right: 0.4rem; }
      table { display: block; width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
      th, td { padding: 0.6rem 0.65rem; }
      table.links-stats-table th,
      table.links-stats-table td { vertical-align: top; }
      .links-stats-table td.cell-actions { vertical-align: middle; white-space: normal; min-width: 0; }
      th { white-space: nowrap; }
      .url-preview { padding: 0.6rem; }
    }
    @media (max-width: 420px) {
      nav { grid-template-columns: 1fr; }
      .mode-toggles { flex-direction: column; }
    }
    {{ final_actions_css | safe }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>Generated Links</h1>
      <nav>
        <a href="/">Hits</a>
        <a href="/links">Links</a>
        <a href="/settings">Settings</a>
        <a href="/nginx">Nginx config</a>
      </nav>
    </header>
    {% if created_url %}
    <section class="card created">
      <h2>Link created</h2>
      <p class="muted" id="copy-status">Attempting to copy the generated link.</p>
      <input type="text" id="created-url" value="{{ created_url }}" readonly>
    </section>
    {% endif %}
    {% if error %}<section class="card"><p style="color:var(--red);">{{ error }}</p></section>{% endif %}
    <section class="card">
      <h2>Create a Link</h2>
      <p class="muted">Settings below are cloned from the selected host by default. After creation, each link has its own saved settings.</p>
      <form method="post" action="/links" id="link-form">
        <div class="grid">
          <div>
            <label for="host">Host</label>
            <select id="host" name="host">
              {% for h in hosts %}
              <option value="{{ h }}" {{ 'selected' if h == selected_host else '' }}>{{ h }}</option>
              {% endfor %}
            </select>
          </div>
          <div>
            <label for="label">Label</label>
            <input type="text" id="label" name="label" value="" placeholder="Optional campaign name" maxlength="200">
          </div>
          <div>
            <label for="custom_token">Custom URL text</label>
            <input type="text" id="custom_token" name="custom_token" value="" placeholder="Optional; random if blank" maxlength="96">
            <p class="muted" style="margin:0.25rem 0 0;">Blank uses a secure random `/l/...` link. Custom text creates a root path like `/not-a-honeypot`; spaces become dashes.</p>
            <div class="url-preview" id="custom-url-preview-box">
              <code id="custom-url-preview"></code>
              <p class="muted" id="custom-url-limits" style="margin:0.35rem 0 0;"></p>
            </div>
          </div>
        </div>
        <div class="fa-scope" id="link-create-fa-scope">
          <div class="fa-random-row">
            <label><input type="checkbox" class="fa-random-toggle" {{ 'checked' if settings.get('random_actions_enabled') else '' }}> Randomize final action</label>
            <span class="hint">Pick one outcome at random per visitor (up to {{ max_final_actions }} actions).</span>
          </div>
          <div class="fa-multi-wrap" hidden>
            <div class="fa-toolbar">
              <span>Actions</span>
              <span class="fa-count-badge" aria-live="polite">0</span>
              <button type="button" class="fa-btn-add">+ Add action</button>
              <button type="button" class="fa-btn-clear">Clear all</button>
            </div>
            <div class="fa-empty visible">No actions yet.</div>
            <div class="fa-actions-list"></div>
          </div>
          <div class="fa-single-wrap">
        <div class="mode-toggles" role="group" aria-label="Final action mode">
          <button type="button" class="mode-btn {{ 'active' if settings.get('mode') == 'redirect' else '' }}" data-mode="redirect">Redirect</button>
          <button type="button" class="mode-btn {{ 'active' if settings.get('mode') == 'media' else '' }}" data-mode="media">Media</button>
          <button type="button" class="mode-btn {{ 'active' if settings.get('mode') == 'error' else '' }}" data-mode="error">Error</button>
        </div>
        <input type="hidden" name="mode" id="mode-input" value="{{ settings.get('mode', 'error') }}">
        <div class="panel {{ 'active' if settings.get('mode') == 'redirect' else '' }}" data-panel="redirect">
          <label for="default_redirect_url">Redirect URL</label>
          <input type="text" id="default_redirect_url" name="default_redirect_url" value="{{ settings.get('default_redirect_url', '') }}" placeholder="https://example.com">
        </div>
        <div class="panel {{ 'active' if settings.get('mode') == 'media' else '' }}" data-panel="media">
          <div class="grid">
            <div>
              <label for="media_url">Media URL or /media path</label>
              <input type="text" id="media_url" name="media_url" value="{{ settings.get('media_url', '') }}" placeholder="/media/file.mp4 or https://...">
              <label for="link_media_file_select">From /media folder</label>
              <select id="link_media_file_select" class="media-file-select" data-target="media_url">
                <option value="">— Select file (optional) —</option>
              </select>
            </div>
            <div>
              <label for="media_type">Type</label>
              <select id="media_type" name="media_type">
                {% for mt in ['image', 'gif', 'video', 'youtube'] %}
                <option value="{{ mt }}" {{ 'selected' if settings.get('media_type') == mt else '' }}>{{ mt }}</option>
                {% endfor %}
              </select>
            </div>
          </div>
          <div class="grid">
            <div>
              <label for="media_tab_mode">Tab title mode</label>
              <select id="media_tab_mode" name="media_tab_mode">
                {% for tm in ['none', 'static', 'scrolling', 'rotating'] %}
                <option value="{{ tm }}" {{ 'selected' if settings.get('media_tab_mode') == tm else '' }}>{{ tm }}</option>
                {% endfor %}
              </select>
            </div>
            <div>
              <label for="media_tab_static_text">Static title</label>
              <input type="text" id="media_tab_static_text" name="media_tab_static_text" value="{{ settings.get('media_tab_static_text', '') }}" maxlength="500">
            </div>
          </div>
          <label for="media_tab_scrolling_text">Scrolling title</label>
          <input type="text" id="media_tab_scrolling_text" name="media_tab_scrolling_text" value="{{ settings.get('media_tab_scrolling_text', '') }}" maxlength="500">
          <label for="media_tab_rotating_messages">Rotating titles (one per line)</label>
          <textarea id="media_tab_rotating_messages" name="media_tab_rotating_messages" rows="2" maxlength="10000">{{ settings.get('media_tab_rotating_messages', '') }}</textarea>
          <label for="media_tab_rotate_interval_sec">Rotate interval seconds</label>
          <input type="number" id="media_tab_rotate_interval_sec" name="media_tab_rotate_interval_sec" value="{{ settings.get('media_tab_rotate_interval_sec', 3) }}" min="1" max="60" style="max-width:6rem;">
        </div>
        <div class="panel {{ 'active' if settings.get('mode') == 'error' else '' }}" data-panel="error">
          <label for="status_code">HTTP status</label>
          <select id="status_code" name="status_code">
            {% for code, label in status_options %}
            <option value="{{ code }}" {{ 'selected' if settings.get('status_code') == code else '' }}>{{ label }}</option>
            {% endfor %}
          </select>
        </div>
          </div>
          <script type="application/json" id="link-create-fa-initial">{{ settings | tojson }}</script>
        </div>
        <input type="hidden" name="action_settings_json" id="action-settings-json" value="">
        <button type="submit">Generate and copy link</button>
      </form>
    </section>
    {{ final_action_template | safe }}
    <section class="card">
      <div style="display:flex;justify-content:space-between;gap:1rem;align-items:center;flex-wrap:wrap;">
        <h2>Link Stats</h2>
        <form method="get" action="/links" style="display:flex;gap:0.5rem;align-items:center;">
          <input type="hidden" name="host" value="{{ selected_host }}">
          <label for="sort" style="margin:0;">Sort</label>
          <select id="sort" name="sort" onchange="this.form.submit()">
            {% for key, label in sort_options %}
            <option value="{{ key }}" {{ 'selected' if sort == key else '' }}>{{ label }}</option>
            {% endfor %}
          </select>
        </form>
      </div>
      {% if links %}
      <table class="links-stats-table">
        <thead><tr><th>Link</th><th>Host</th><th>Mode</th><th>Total</th><th>Unique IPs</th><th>Last hit</th><th class="links-stats-actions-header" aria-label="Actions"></th></tr></thead>
        <tbody>
          {% for link in links %}
          {% set lp = link.get('path') or '' %}
          <tr class="{{ '' if link.get('active') else 'inactive' }}">
            <td class="link-cell">
              <div class="link-meta">
                <div class="link-dest-muted">{{ link.get('label') or '(unlabeled)' }}</div>
                <div class="token">{{ link.get('token') }}</div>
                <div class="link-url-row">
                  <a class="full-url-anchor" href="{{ link.get('full_url') }}" target="_blank" rel="noopener noreferrer">{{ link.get('full_url') }}</a>
                  <button type="button" class="btn-copy-mini" data-copy-url="{{ link.get('full_url') }}" aria-label="Copy honeypot link">Copy</button>
                </div>
                {% if lp.startswith('/l/') %}
                <p class="link-path-kind">Standard tracked URL (<code>/l/</code> + random token).</p>
                {% else %}
                <p class="link-path-kind">Custom root path <code>{{ lp }}</code> (no <code>/l/</code> prefix).</p>
                {% endif %}
              </div>
            </td>
            <td>{{ link.get('host') }}</td>
            <td>{% set ls = link.get('settings') or {} %}{% if ls.get('random_actions_enabled') and ls.get('actions') %}random ({{ ls.get('actions')|length }}){% else %}{{ ls.get('mode', 'error') }}{% endif %}</td>
            <td>{{ link.get('total_hits', 0) }}</td>
            <td>{{ link.get('unique_ips', 0) }}</td>
            <td>{{ format_ts_readable(link.get('last_hit'), timezone) }}</td>
            <td class="cell-actions"><a class="action-link" href="/links/{{ link.get('_id') }}">Details</a><a class="action-link" href="/?link={{ link.get('_id') }}">Hits</a></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="muted">No generated links yet.</p>
      {% endif %}
    </section>
  </div>
  <script>
    {{ final_actions_js | safe }}
    (function() {
      var host = document.getElementById('host');
      if (host) {
        host.addEventListener('change', function() {
          window.location.href = '/links?host=' + encodeURIComponent(host.value);
        });
      }
      var linkFaScope = document.getElementById('link-create-fa-scope');
      var linkFaBoot = document.getElementById('link-create-fa-initial');
      if (linkFaScope && typeof initFinalActionsScope === 'function') {
        var linkInitial = {};
        if (linkFaBoot && linkFaBoot.textContent) {
          try { linkInitial = JSON.parse(linkFaBoot.textContent); } catch (e0) { linkInitial = {}; }
        }
        initFinalActionsScope(linkFaScope, linkInitial);
      }
      var linkForm = document.getElementById('link-form');
      if (linkForm) {
        linkForm.addEventListener('submit', function() {
          if (linkFaScope && typeof serializeFinalActionsScope === 'function') {
            var out = document.getElementById('action-settings-json');
            if (out) out.value = JSON.stringify(serializeFinalActionsScope(linkFaScope));
          }
        });
      }
      var modeInput = document.getElementById('mode-input');
      var singleWrap = linkFaScope ? linkFaScope.querySelector('.fa-single-wrap') : null;
      function setMode(mode) {
        if (modeInput) modeInput.value = mode;
        var root = singleWrap || document;
        root.querySelectorAll('.mode-btn').forEach(function(btn) { btn.classList.toggle('active', btn.dataset.mode === mode); });
        root.querySelectorAll('[data-panel]').forEach(function(panel) { panel.classList.toggle('active', panel.dataset.panel === mode); });
      }
      if (singleWrap) {
        singleWrap.querySelectorAll('.mode-btn').forEach(function(btn) {
          btn.addEventListener('click', function() { setMode(btn.dataset.mode); });
        });
      }
      function bindCustomUrlPreview() {
        var input = document.getElementById('custom_token');
        var hostSelect = document.getElementById('host');
        var preview = document.getElementById('custom-url-preview');
        var limits = document.getElementById('custom-url-limits');
        var box = document.getElementById('custom-url-preview-box');
        if (!input || !hostSelect || !preview || !limits || !box) return;
        var scheme = {{ tracked_link_scheme|tojson }};
        var maxCustom = {{ custom_token_max_len }};
        var maxUrl = {{ max_generated_url_len }};
        var reserved = {{ reserved_link_tokens|tojson }};
        function normalize(raw) {
          var value = (raw || '').trim();
          if (value.indexOf('/l/') === 0) value = value.slice(3);
          value = value.replace(/^\\/+|\\/+$/g, '').replace(/\\s+/g, '-');
          if (value.length > maxCustom) value = value.slice(0, maxCustom);
          return value;
        }
        function update() {
          var host = (hostSelect.value || '').trim();
          var origin = scheme + '://' + host;
          var slug = normalize(input.value);
          var isBlank = !(input.value || '').trim();
          var path = isBlank ? '/l/<random-token>' : '/' + slug;
          var url = origin + path;
          var maxForHost = Math.max(0, maxUrl - origin.length - 1);
          var valid = isBlank || /^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$/.test(slug);
          var isReserved = !isBlank && reserved.indexOf(slug.toLowerCase()) !== -1;
          preview.textContent = url;
          box.classList.toggle('error', !valid || isReserved || url.length > maxUrl);
          box.classList.toggle('warning', isBlank);
          if (isBlank) {
            limits.textContent = 'Random links use a secure token. Full preview length with this domain is ' + url.length + '/' + maxUrl + ' characters.';
          } else if (isReserved) {
            limits.textContent = 'This path is reserved by the app. Choose different URL text.';
          } else if (!valid) {
            limits.textContent = 'Use 3-' + maxCustom + ' characters: letters, numbers, dots, dashes, or underscores. The first character must be a letter or number.';
          } else {
            limits.textContent = 'Custom text: ' + slug.length + '/' + maxCustom + ' characters. Full URL: ' + url.length + '/' + maxUrl + ' characters. With this domain, up to ' + Math.min(maxCustom, maxForHost) + ' custom characters fit.';
          }
        }
        input.addEventListener('input', update);
        hostSelect.addEventListener('change', update);
        update();
      }
      bindCustomUrlPreview();
      function bindMediaSelectors() {
        var selects = Array.prototype.slice.call(document.querySelectorAll('.media-file-select'));
        if (!selects.length) return;
        fetch('/api/media-files', { credentials: 'same-origin' }).then(function(r) { return r.json(); }).then(function(files) {
          selects.forEach(function(sel) {
            var target = document.getElementById(sel.getAttribute('data-target'));
            while (sel.options.length > 1) sel.remove(1);
            (files || []).forEach(function(f) {
              var opt = document.createElement('option');
              opt.value = '/media/' + f;
              opt.textContent = f;
              sel.appendChild(opt);
            });
            if (target && target.value && target.value.indexOf('/media/') === 0) sel.value = target.value;
            sel.addEventListener('change', function() {
              if (this.value && target) target.value = this.value;
            });
          });
        }).catch(function() {});
      }
      bindMediaSelectors();
      document.querySelectorAll('button.btn-copy-mini[data-copy-url]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var url = btn.getAttribute('data-copy-url') || '';
          function revert() {
            btn.classList.remove('copied');
            btn.textContent = 'Copy';
          }
          function done(ok) {
            btn.classList.add('copied');
            btn.textContent = ok ? 'Copied!' : 'Copy failed';
            setTimeout(revert, 2000);
          }
          if (!url) return;
          if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(url).then(function() { done(true); }).catch(function() { done(false); });
          } else {
            try {
              var ta = document.createElement('textarea');
              ta.value = url;
              ta.setAttribute('readonly', '');
              ta.style.position = 'fixed';
              ta.style.opacity = '0';
              document.body.appendChild(ta);
              ta.select();
              document.execCommand('copy');
              document.body.removeChild(ta);
              done(true);
            } catch (e) {
              done(false);
            }
          }
        });
      });
      var created = document.getElementById('created-url');
      if (created) {
        var status = document.getElementById('copy-status');
        var value = created.value;
        function fallback() {
          created.focus();
          created.select();
          if (status) status.textContent = 'Copy did not complete automatically; the link is selected.';
        }
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(value).then(function() {
            if (status) status.textContent = 'Copied generated link to clipboard.';
          }).catch(fallback);
        } else {
          fallback();
        }
      }
    })();
  </script>
</body>
</html>
"""


LINK_DETAIL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Link Details - Honeytoken Admin</title>
  <style>
    :root { --bg: #0a0a0b; --surface: #141416; --border: #27272a; --muted: #71717a; --text: #fafafa; --accent: #3b82f6; --green: #22c55e; --amber: #f59e0b; }
    * { box-sizing: border-box; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin:0; background:var(--bg); color:var(--text); }
    .wrap { max-width: 58rem; margin: 0 auto; padding: 1.5rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1rem; margin-bottom:1rem; }
    .muted { color:var(--muted); font-size:0.875rem; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(12rem,1fr)); gap:0.75rem 1rem; }
    label { display:block; color:var(--muted); font-size:0.8rem; margin:0.75rem 0 0.25rem; }
    input[type=text], input[type=number], select, textarea { width:100%; padding:0.5rem 0.65rem; background:var(--bg); border:1px solid var(--border); color:var(--text); border-radius:6px; font-size:0.875rem; }
    textarea { resize:vertical; font-family:inherit; }
    button { margin-top:1rem; padding:0.5rem 0.85rem; background:var(--accent); color:#fff; border:none; border-radius:6px; cursor:pointer; }
    .mode-toggles { display:flex; gap:0; margin:0.75rem 0; background:var(--bg); border-radius:8px; padding:4px; border:1px solid var(--border); max-width:28rem; }
    .mode-btn { flex:1; background:transparent; color:var(--muted); margin:0; }
    .mode-btn.active { background:var(--accent); color:#fff; }
    .panel { display:none; }
    .panel.active { display:block; }
    table { width:100%; border-collapse:collapse; font-size:0.875rem; }
    td, th { padding:0.5rem; border-bottom:1px solid var(--border); text-align:left; }
    th { color:var(--muted); }
    .token { font-family:ui-monospace,monospace; color:var(--amber); }
    .tracked-url-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.45rem 0.65rem; margin: 0.35rem 0 0; }
    .tracked-url-row .full-url-anchor-detail { font-family: ui-monospace, monospace; font-size: 0.875rem; color: var(--green); overflow-wrap: anywhere; }
    button.btn-copy-mini {
      flex-shrink: 0;
      font-size: 0.75rem;
      padding: 0.28rem 0.55rem;
      margin-top: 0 !important;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 5px;
      cursor: pointer;
      font-family: inherit;
      line-height: 1.2;
    }
    button.btn-copy-mini:hover { border-color: var(--accent); color: var(--accent); background: var(--surface); }
    button.btn-copy-mini.copied { border-color: var(--green); color: var(--green); }
    .saved { color:var(--green); }
    @media (max-width: 760px) {
      .wrap { max-width: 100%; padding: 0.85rem; overflow-x: hidden; }
      h1 { font-size: 1.15rem; overflow-wrap: anywhere; }
      .card { padding: 0.85rem; border-radius: 8px; }
      .grid { grid-template-columns: 1fr; gap: 0.75rem; }
      input[type=text], input[type=number], select, textarea, button { min-height: 2.5rem; font-size: 1rem; }
      button.btn-copy-mini { min-height: 0; font-size: 0.75rem; padding: 0.35rem 0.55rem; }
      .mode-toggles { max-width: none; }
      table { display: block; width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
      td, th { padding: 0.6rem 0.65rem; }
      .muted { line-height: 1.5; }
    }
    @media (max-width: 420px) {
      .mode-toggles { flex-direction: column; }
    }
    {{ final_actions_css | safe }}
  </style>
</head>
<body>
  <div class="wrap">
    <p class="muted"><a href="/links">&larr; Links</a> · <a href="/">Hits</a></p>
    <h1>{{ link.get('label') or 'Generated link' }}</h1>
    {% if saved %}<p class="saved">Saved.</p>{% endif %}
    <section class="card">
      <p class="muted" style="margin:0 0 0.15rem;"><span class="token">{{ link.get('token') }}</span></p>
      <div class="tracked-url-row">
        <a class="full-url-anchor-detail" href="{{ full_url }}" target="_blank" rel="noopener noreferrer">{{ full_url }}</a>
        <button type="button" class="btn-copy-mini" data-copy-url="{{ full_url }}" aria-label="Copy honeypot link">Copy</button>
      </div>
      <div class="grid">
        <div><strong>{{ link.get('total_hits', 0) }}</strong><div class="muted">Total hits</div></div>
        <div><strong>{{ link.get('unique_ips', 0) }}</strong><div class="muted">Unique IPs</div></div>
        <div><strong>{{ format_ts_readable(link.get('last_hit'), timezone) }}</strong><div class="muted">Last hit</div></div>
        <div><strong>{{ 'Active' if link.get('active') else 'Inactive' }}</strong><div class="muted">Status</div></div>
      </div>
      <p><a href="/?link={{ link.get('_id') }}">View hits for this link</a></p>
    </section>
    <section class="card">
      <h2>Edit Link</h2>
      <form method="post" action="/links/{{ link.get('_id') }}" id="link-form">
        <label for="label">Label</label>
        <input type="text" id="label" name="label" value="{{ link.get('label', '') }}" maxlength="200">
        <label style="display:flex;align-items:center;gap:0.5rem;"><input type="checkbox" name="active" value="1" {{ 'checked' if link.get('active') else '' }} style="width:auto;"> Active</label>
        {% set settings = link.get('settings') or {} %}
        <div class="fa-scope" id="link-detail-fa-scope">
          <div class="fa-random-row">
            <label><input type="checkbox" class="fa-random-toggle" {{ 'checked' if settings.get('random_actions_enabled') else '' }}> Randomize final action</label>
            <span class="hint">Pick one outcome at random per visitor (up to {{ max_final_actions }} actions).</span>
          </div>
          <div class="fa-multi-wrap" hidden>
            <div class="fa-toolbar">
              <span>Actions</span>
              <span class="fa-count-badge" aria-live="polite">0</span>
              <button type="button" class="fa-btn-add">+ Add action</button>
              <button type="button" class="fa-btn-clear">Clear all</button>
            </div>
            <div class="fa-empty visible">No actions yet.</div>
            <div class="fa-actions-list"></div>
          </div>
          <div class="fa-single-wrap">
        <div class="mode-toggles" role="group" aria-label="Final action mode">
          <button type="button" class="mode-btn {{ 'active' if settings.get('mode') == 'redirect' else '' }}" data-mode="redirect">Redirect</button>
          <button type="button" class="mode-btn {{ 'active' if settings.get('mode') == 'media' else '' }}" data-mode="media">Media</button>
          <button type="button" class="mode-btn {{ 'active' if settings.get('mode') == 'error' else '' }}" data-mode="error">Error</button>
        </div>
        <input type="hidden" name="mode" id="mode-input" value="{{ settings.get('mode', 'error') }}">
        <div class="panel {{ 'active' if settings.get('mode') == 'redirect' else '' }}" data-panel="redirect">
          <label for="default_redirect_url">Redirect URL</label>
          <input type="text" id="default_redirect_url" name="default_redirect_url" value="{{ settings.get('default_redirect_url', '') }}">
        </div>
        <div class="panel {{ 'active' if settings.get('mode') == 'media' else '' }}" data-panel="media">
          <label for="media_url">Media URL or /media path</label>
          <input type="text" id="media_url" name="media_url" value="{{ settings.get('media_url', '') }}">
          <label for="detail_media_file_select">From /media folder</label>
          <select id="detail_media_file_select" class="media-file-select" data-target="media_url">
            <option value="">— Select file (optional) —</option>
          </select>
          <label for="media_type">Type</label>
          <select id="media_type" name="media_type">
            {% for mt in ['image', 'gif', 'video', 'youtube'] %}
            <option value="{{ mt }}" {{ 'selected' if settings.get('media_type') == mt else '' }}>{{ mt }}</option>
            {% endfor %}
          </select>
          <label for="media_tab_mode">Tab title mode</label>
          <select id="media_tab_mode" name="media_tab_mode">
            {% for tm in ['none', 'static', 'scrolling', 'rotating'] %}
            <option value="{{ tm }}" {{ 'selected' if settings.get('media_tab_mode') == tm else '' }}>{{ tm }}</option>
            {% endfor %}
          </select>
          <label for="media_tab_static_text">Static title</label>
          <input type="text" id="media_tab_static_text" name="media_tab_static_text" value="{{ settings.get('media_tab_static_text', '') }}" maxlength="500">
          <label for="media_tab_scrolling_text">Scrolling title</label>
          <input type="text" id="media_tab_scrolling_text" name="media_tab_scrolling_text" value="{{ settings.get('media_tab_scrolling_text', '') }}" maxlength="500">
          <label for="media_tab_rotating_messages">Rotating titles</label>
          <textarea id="media_tab_rotating_messages" name="media_tab_rotating_messages" rows="2" maxlength="10000">{{ settings.get('media_tab_rotating_messages', '') }}</textarea>
          <label for="media_tab_rotate_interval_sec">Rotate interval seconds</label>
          <input type="number" id="media_tab_rotate_interval_sec" name="media_tab_rotate_interval_sec" value="{{ settings.get('media_tab_rotate_interval_sec', 3) }}" min="1" max="60" style="max-width:6rem;">
        </div>
        <div class="panel {{ 'active' if settings.get('mode') == 'error' else '' }}" data-panel="error">
          <label for="status_code">HTTP status</label>
          <select id="status_code" name="status_code">
            {% for code, label in status_options %}
            <option value="{{ code }}" {{ 'selected' if settings.get('status_code') == code else '' }}>{{ label }}</option>
            {% endfor %}
          </select>
        </div>
          </div>
          <script type="application/json" id="link-detail-fa-initial">{{ settings | tojson }}</script>
        </div>
        <input type="hidden" name="action_settings_json" id="action-settings-json" value="">
        <button type="submit">Save link</button>
      </form>
    </section>
    {{ final_action_template | safe }}
    <section class="card">
      <h2>Breakdown</h2>
      <div class="grid">
        <div>
          <h3>Hosts</h3>
          <table>{% for row in link.get('by_host', []) %}<tr><td>{{ row.host or 'unknown' }}</td><td>{{ row.count }}</td></tr>{% endfor %}</table>
        </div>
        <div>
          <h3>Paths</h3>
          <table>{% for row in link.get('by_path', []) %}<tr><td>{{ row.path or 'unknown' }}</td><td>{{ row.count }}</td></tr>{% endfor %}</table>
        </div>
      </div>
    </section>
  </div>
  <script>
    {{ final_actions_js | safe }}
    (function() {
      var detailFaScope = document.getElementById('link-detail-fa-scope');
      var detailFaBoot = document.getElementById('link-detail-fa-initial');
      if (detailFaScope && typeof initFinalActionsScope === 'function') {
        var detailInitial = {};
        if (detailFaBoot && detailFaBoot.textContent) {
          try { detailInitial = JSON.parse(detailFaBoot.textContent); } catch (e0) { detailInitial = {}; }
        }
        initFinalActionsScope(detailFaScope, detailInitial);
      }
      var detailForm = document.getElementById('link-form');
      if (detailForm) {
        detailForm.addEventListener('submit', function() {
          if (detailFaScope && typeof serializeFinalActionsScope === 'function') {
            var out = document.getElementById('action-settings-json');
            if (out) out.value = JSON.stringify(serializeFinalActionsScope(detailFaScope));
          }
        });
      }
      var modeInput = document.getElementById('mode-input');
      var singleWrap = detailFaScope ? detailFaScope.querySelector('.fa-single-wrap') : null;
      function setMode(mode) {
        if (modeInput) modeInput.value = mode;
        var root = singleWrap || document;
        root.querySelectorAll('.mode-btn').forEach(function(btn) { btn.classList.toggle('active', btn.dataset.mode === mode); });
        root.querySelectorAll('[data-panel]').forEach(function(panel) { panel.classList.toggle('active', panel.dataset.panel === mode); });
      }
      if (singleWrap) {
        singleWrap.querySelectorAll('.mode-btn').forEach(function(btn) {
          btn.addEventListener('click', function() { setMode(btn.dataset.mode); });
        });
      }
      function bindMediaSelectors() {
        var selects = Array.prototype.slice.call(document.querySelectorAll('.media-file-select'));
        if (!selects.length) return;
        fetch('/api/media-files', { credentials: 'same-origin' }).then(function(r) { return r.json(); }).then(function(files) {
          selects.forEach(function(sel) {
            var target = document.getElementById(sel.getAttribute('data-target'));
            while (sel.options.length > 1) sel.remove(1);
            (files || []).forEach(function(f) {
              var opt = document.createElement('option');
              opt.value = '/media/' + f;
              opt.textContent = f;
              sel.appendChild(opt);
            });
            if (target && target.value && target.value.indexOf('/media/') === 0) sel.value = target.value;
            sel.addEventListener('change', function() {
              if (this.value && target) target.value = this.value;
            });
          });
        }).catch(function() {});
      }
      bindMediaSelectors();
      document.querySelectorAll('button.btn-copy-mini[data-copy-url]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var url = btn.getAttribute('data-copy-url') || '';
          function revert() {
            btn.classList.remove('copied');
            btn.textContent = 'Copy';
          }
          function done(ok) {
            btn.classList.add('copied');
            btn.textContent = ok ? 'Copied!' : 'Copy failed';
            setTimeout(revert, 2000);
          }
          if (!url) return;
          if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(url).then(function() { done(true); }).catch(function() { done(false); });
          } else {
            try {
              var ta = document.createElement('textarea');
              ta.value = url;
              ta.setAttribute('readonly', '');
              ta.style.position = 'fixed';
              ta.style.opacity = '0';
              document.body.appendChild(ta);
              ta.select();
              document.execCommand('copy');
              document.body.removeChild(ta);
              done(true);
            } catch (e) {
              done(false);
            }
          }
        });
      });
    })();
  </script>
</body>
</html>
"""


SETTINGS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Settings – Honeytoken Admin</title>
  <style>
    :root { --bg: #0a0a0b; --surface: #141416; --border: #27272a; --muted: #71717a; --text: #fafafa; --accent: #3b82f6; --green: #22c55e; }
    * { box-sizing: border-box; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); min-height: 100vh; }
    .wrap { max-width: 32rem; margin: 0 auto; padding: 1.5rem; }
    h1 { font-size: 1.25rem; margin-bottom: 0.5rem; }
    .meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .mode-toggles { display: flex; gap: 0; margin-bottom: 1.5rem; background: var(--surface); border-radius: 8px; padding: 4px; border: 1px solid var(--border); }
    .mode-btn { flex: 1; padding: 0.6rem 1rem; border: none; border-radius: 6px; background: transparent; color: var(--muted); cursor: pointer; font-size: 0.875rem; }
    .mode-btn.active { background: var(--accent); color: #fff; }
    .mode-btn:not(.active):hover { color: var(--text); }
    .panel { display: none; margin-top: 1rem; }
    .panel.active { display: block; }
    label { display: block; margin-top: 1rem; color: var(--muted); font-size: 0.875rem; }
    input[type=text], select { width: 100%; padding: 0.5rem 0.75rem; margin-top: 0.25rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); border-radius: 6px; font-size: 0.875rem; }
    select { cursor: pointer; }
    .hint { color: var(--muted); font-size: 0.8rem; margin-top: 0.25rem; }
    button[type=submit] { margin-top: 1.25rem; padding: 0.5rem 1.25rem; background: var(--accent); color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
    button[type=submit]:hover { background: #2563eb; }
    .saved { color: var(--green); font-size: 0.875rem; margin-top: 0.5rem; }
    .section-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-top: 1.5rem; margin-bottom: 0.5rem; }
    .host-blocks { margin-top: 1rem; }
    .host-block { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
    .host-block-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .host-name { font-weight: 600; font-size: 0.9rem; }
    .host-remove { padding: 0.25rem 0.5rem; font-size: 0.75rem; background: transparent; color: var(--muted); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; }
    .host-remove:hover { color: #ef4444; border-color: #ef4444; }
    .add-host-row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; margin-top: 0.5rem; }
    .add-host-row input[type=text] { flex: 1; min-width: 10rem; }
    .add-host-row select { min-width: 8rem; }
    .add-host-row button { padding: 0.4rem 0.75rem; font-size: 0.875rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); border-radius: 6px; cursor: pointer; }
    .add-host-row button:hover { border-color: var(--accent); color: var(--accent); }
    .media-tab-panel, .host-tab-panel { display: none; margin-top: 0.75rem; }
    .media-tab-panel.active, .host-tab-panel.active { display: block; }
    textarea { font-family: inherit; resize: vertical; }
    .nr-panel { margin-top: 1rem; padding: 1rem 1rem 1.25rem; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; }
    .nr-toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.75rem; }
    .nr-toolbar-title { font-weight: 600; font-size: 0.95rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
    .nr-badge { display: inline-flex; align-items: center; justify-content: center; min-width: 1.5rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; background: var(--border); color: var(--text); }
    .nr-btn-add { padding: 0.45rem 0.9rem; font-size: 0.875rem; background: var(--accent); color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 500; }
    .nr-btn-add:hover { background: #2563eb; }
    .nr-summary-line { color: var(--muted); font-size: 0.8rem; margin: 0 0 0.75rem; line-height: 1.45; }
    .nr-empty { display: none; text-align: center; padding: 1.25rem 1rem; margin-bottom: 0.75rem; border: 1px dashed var(--border); border-radius: 8px; color: var(--muted); font-size: 0.875rem; line-height: 1.5; }
    .nr-empty.visible { display: block; }
    .nr-rules-list { display: flex; flex-direction: column; gap: 0.75rem; }
    .nr-block { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
    .nr-block-top { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 0.65rem; margin-bottom: 0.85rem; padding-bottom: 0.65rem; border-bottom: 1px solid var(--border); }
    .nr-title-stack { display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; flex: 1; }
    .nr-rule-line { display: flex; flex-wrap: wrap; align-items: center; gap: 0.45rem; font-size: 0.875rem; }
    .nr-rule-number { color: var(--muted); font-weight: 500; }
    .nr-rule-display-title { font-weight: 600; color: var(--text); word-break: break-word; }
    .nr-status-badge { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; padding: 0.2rem 0.45rem; border-radius: 4px; }
    .nr-status-on { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
    .nr-status-off { background: rgba(113, 113, 122, 0.25); color: var(--muted); }
    .nr-btn-danger { padding: 0.35rem 0.65rem; font-size: 0.75rem; background: transparent; color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.45); border-radius: 6px; cursor: pointer; flex-shrink: 0; }
    .nr-btn-danger:hover { background: rgba(239, 68, 68, 0.12); border-color: #ef4444; }
    .nr-save-reminder { margin-top: 0.75rem; padding: 0.65rem 0.75rem; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.25); border-radius: 8px; font-size: 0.8rem; line-height: 1.45; }
    .nr-btn-test { padding: 0.4rem 0.75rem; font-size: 0.8rem; background: transparent; border: 1px solid var(--border); color: var(--accent); border-radius: 6px; cursor: pointer; }
    .nr-btn-test:hover:not(:disabled) { border-color: var(--accent); background: rgba(59, 130, 246, 0.1); }
    .nr-btn-test:disabled { opacity: 0.55; cursor: not-allowed; }
    .nr-test-row { margin-top: 0.35rem; padding-top: 0.85rem; border-top: 1px solid var(--border); }
    .nr-block-header { display: flex; justify-content: flex-start; align-items: flex-start; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.75rem; }
    .nr-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem 1rem; }
    .nr-grid-full { grid-column: 1 / -1; }
    @media (max-width: 760px) {
      .wrap { max-width: 100%; padding: 0.85rem; overflow-x: hidden; }
      h1 { font-size: 1.15rem; }
      .meta { line-height: 1.7; }
      .mode-toggles { flex-direction: column; gap: 0.35rem; }
      .mode-btn { min-height: 2.5rem; }
      label { margin-top: 0.8rem; }
      input[type=text], input[type=number], select, textarea, button[type=submit] { min-height: 2.5rem; font-size: 1rem; }
      .host-block { padding: 0.85rem; border-radius: 8px; }
      .host-block-header { align-items: stretch; flex-direction: column; gap: 0.5rem; }
      .host-remove { min-height: 2.25rem; }
      .add-host-row { align-items: stretch; flex-direction: column; }
      .add-host-row input[type=text], .add-host-row select, .add-host-row button { width: 100%; min-width: 0; min-height: 2.5rem; }
      .nr-grid { grid-template-columns: 1fr; }
      .nr-block-top { flex-direction: column; align-items: stretch; }
      .nr-btn-danger { min-height: 2.25rem; width: 100%; }
    }
    {{ final_actions_css | safe }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Settings</h1>
    <p class="meta"><a href="/">← Dashboard</a> · <a href="/links">Links</a> · <a href="/nginx">Nginx config</a></p>
    <p style="color: var(--muted); font-size: 0.875rem;">Configure the <strong>final action</strong> after client-side capture.</p>
    <form method="post" action="/settings" id="settings-form">
      <p class="section-label">Display</p>
      <label for="timezone">Dashboard timezone</label>
      <select id="timezone" name="timezone">
        {% set tz_vals = ['America/Chicago', 'America/New_York', 'America/Denver', 'America/Phoenix', 'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu', 'UTC', 'Europe/London', 'Europe/Paris', 'Asia/Tokyo', 'Australia/Sydney'] %}
        {% if timezone not in tz_vals %}
        <option value="{{ timezone }}" selected>{{ timezone }}</option>
        {% endif %}
        <option value="America/Chicago" {{ 'selected' if timezone == 'America/Chicago' else '' }}>Central (Chicago)</option>
        <option value="America/New_York" {{ 'selected' if timezone == 'America/New_York' else '' }}>Eastern (New York)</option>
        <option value="America/Denver" {{ 'selected' if timezone == 'America/Denver' else '' }}>Mountain (Denver)</option>
        <option value="America/Phoenix" {{ 'selected' if timezone == 'America/Phoenix' else '' }}>Arizona (Phoenix)</option>
        <option value="America/Los_Angeles" {{ 'selected' if timezone == 'America/Los_Angeles' else '' }}>Pacific (Los Angeles)</option>
        <option value="America/Anchorage" {{ 'selected' if timezone == 'America/Anchorage' else '' }}>Alaska (Anchorage)</option>
        <option value="Pacific/Honolulu" {{ 'selected' if timezone == 'Pacific/Honolulu' else '' }}>Hawaii (Honolulu)</option>
        <option value="UTC" {{ 'selected' if timezone == 'UTC' else '' }}>UTC</option>
        <option value="Europe/London" {{ 'selected' if timezone == 'Europe/London' else '' }}>Europe/London</option>
        <option value="Europe/Paris" {{ 'selected' if timezone == 'Europe/Paris' else '' }}>Europe/Paris</option>
        <option value="Asia/Tokyo" {{ 'selected' if timezone == 'Asia/Tokyo' else '' }}>Asia/Tokyo</option>
        <option value="Australia/Sydney" {{ 'selected' if timezone == 'Australia/Sydney' else '' }}>Australia/Sydney</option>
      </select>
      <p class="hint">Times on the Hits dashboard are shown in this timezone. UTC is always available in row details.</p>
      <p class="section-label">Default (all hosts)</p>
      <div class="fa-scope" id="default-fa-scope">
        <div class="fa-random-row">
          <label><input type="checkbox" class="fa-random-toggle" {{ 'checked' if action_settings_initial.get('random_actions_enabled') else '' }}> Randomize final action</label>
          <span class="hint">When enabled, each visitor gets one action picked at random from your list (up to {{ max_final_actions }}). Otherwise the single action below is always used.</span>
        </div>
        <div class="fa-multi-wrap" hidden>
          <div class="fa-toolbar">
            <span>Actions</span>
            <span class="fa-count-badge" aria-live="polite">0</span>
            <button type="button" class="fa-btn-add">+ Add action</button>
            <button type="button" class="fa-btn-clear">Clear all</button>
          </div>
          <p class="hint" style="margin:0 0 0.65rem;font-size:0.78rem;">Add, edit, or delete individual outcomes. Save at the bottom to persist.</p>
          <div class="fa-empty visible">No actions yet. Click <strong>+ Add action</strong> or turn off randomize to use a single action.</div>
          <div class="fa-actions-list"></div>
        </div>
        <div class="fa-single-wrap">
      <div class="mode-toggles" role="group" aria-label="Final action mode">
        <button type="button" class="mode-btn {{ 'active' if mode == 'redirect' else '' }}" data-mode="redirect">Redirect</button>
        <button type="button" class="mode-btn {{ 'active' if mode == 'media' else '' }}" data-mode="media">Media</button>
        <button type="button" class="mode-btn {{ 'active' if mode == 'error' else '' }}" data-mode="error">Error</button>
      </div>
      <input type="hidden" name="mode" id="mode-input" value="{{ mode }}">
      <div class="panel {{ 'active' if mode == 'redirect' else '' }}" id="panel-redirect">
        <label for="default_redirect_url">Redirect URL</label>
        <input type="text" id="default_redirect_url" name="default_redirect_url" value="{{ default_redirect_url }}" placeholder="https://example.com">
        <p class="hint">After capture, the visitor is redirected to this URL.</p>
      </div>
      <div class="panel {{ 'active' if mode == 'media' else '' }}" id="panel-media">
        <label for="media_url">Media URL or file</label>
        <input type="text" id="media_url" name="media_url" value="{{ media_url }}" placeholder="https://... or YouTube URL, or pick from /media below">
        <label for="media_file_select">From /media folder</label>
        <select id="media_file_select">
          <option value="">— Select file (optional) —</option>
        </select>
        <p class="hint">Select a file to use its path (/media/...) or enter a URL above. Drop files into the mounted media folder.</p>
        <label for="media_type">Type</label>
        <select id="media_type" name="media_type">
          <option value="image" {{ 'selected' if media_type == 'image' else '' }}>Image</option>
          <option value="gif" {{ 'selected' if media_type == 'gif' else '' }}>GIF</option>
          <option value="video" {{ 'selected' if media_type == 'video' else '' }}>Video</option>
          <option value="youtube" {{ 'selected' if media_type == 'youtube' else '' }}>YouTube</option>
        </select>
        <p class="hint">Page is replaced in-place with the media. YouTube uses autoplay+mute. On load error, fake 404 is shown.</p>
        <p class="section-label" style="margin-top:1.25rem;">Tab title</p>
        <label for="media_tab_mode">Browser tab title</label>
        <select id="media_tab_mode" name="media_tab_mode">
          <option value="none" {{ 'selected' if media_tab_mode == 'none' else '' }}>None</option>
          <option value="static" {{ 'selected' if media_tab_mode == 'static' else '' }}>Static message</option>
          <option value="scrolling" {{ 'selected' if media_tab_mode == 'scrolling' else '' }}>Scrolling message</option>
          <option value="rotating" {{ 'selected' if media_tab_mode == 'rotating' else '' }}>Rotating messages</option>
        </select>
        <div class="panel media-tab-panel media-tab-static {{ 'active' if media_tab_mode == 'static' else '' }}">
          <label for="media_tab_static_text">Static message</label>
          <input type="text" id="media_tab_static_text" name="media_tab_static_text" value="{{ media_tab_static_text }}" placeholder="e.g. Loading..." maxlength="500">
        </div>
        <div class="panel media-tab-panel media-tab-scrolling {{ 'active' if media_tab_mode == 'scrolling' else '' }}">
          <label for="media_tab_scrolling_text">Scrolling message</label>
          <input type="text" id="media_tab_scrolling_text" name="media_tab_scrolling_text" value="{{ media_tab_scrolling_text }}" placeholder="e.g. Please wait..." maxlength="500">
        </div>
        <div class="panel media-tab-panel media-tab-rotating {{ 'active' if media_tab_mode == 'rotating' else '' }}">
          <label for="media_tab_rotating_messages">Rotating messages (one per line)</label>
          <textarea id="media_tab_rotating_messages" name="media_tab_rotating_messages" rows="3" placeholder="Message one&#10;Message two&#10;Message three" maxlength="10000">{{ media_tab_rotating_messages }}</textarea>
          <label for="media_tab_rotate_interval_sec">Switch every (seconds)</label>
          <input type="number" id="media_tab_rotate_interval_sec" name="media_tab_rotate_interval_sec" value="{{ media_tab_rotate_interval_sec }}" min="1" max="60" style="width:5rem;">
        </div>
      </div>
      <div class="panel {{ 'active' if mode == 'error' else '' }}" id="panel-error">
        <label for="status_code">HTTP status</label>
        <select id="status_code" name="status_code">
          {% for code, label in status_options %}
          <option value="{{ code }}" {{ 'selected' if status_code == code else '' }}>{{ label }}</option>
          {% endfor %}
        </select>
        <p class="hint">Nginx-style error page when no redirect or media is set.</p>
      </div>
        </div>
        <script type="application/json" id="fa-default-initial">{{ action_settings_initial | tojson }}</script>
      </div>
      <input type="hidden" name="action_settings_json" id="action-settings-json" value="">
      <p class="section-label">Per-host overrides</p>
      <p class="hint" style="margin-top:0;">Override the final action per host. Hosts not listed use the default above.</p>
      <div id="host-blocks-container" class="host-blocks">
        {% for host, opts in host_settings.items() %}
        <div class="host-block" data-host="{{ host }}">
          <div class="host-block-header">
            <span class="host-name">{{ host }}</span>
            <button type="button" class="host-remove" aria-label="Remove host">Remove</button>
          </div>
          <div class="fa-scope host-fa-scope">
            <div class="fa-random-row">
              <label><input type="checkbox" class="fa-random-toggle" {{ 'checked' if opts.get('random_actions_enabled') else '' }}> Randomize final action</label>
            </div>
            <div class="fa-multi-wrap" hidden>
              <div class="fa-toolbar">
                <span>Actions</span>
                <span class="fa-count-badge" aria-live="polite">0</span>
                <button type="button" class="fa-btn-add">+ Add action</button>
                <button type="button" class="fa-btn-clear">Clear all</button>
              </div>
              <div class="fa-empty visible">No actions in list.</div>
              <div class="fa-actions-list"></div>
            </div>
            <div class="fa-single-wrap">
          <div class="mode-toggles host-mode-toggles" role="group">
            <button type="button" class="mode-btn {{ 'active' if opts.get('mode') == 'redirect' else '' }}" data-mode="redirect">Redirect</button>
            <button type="button" class="mode-btn {{ 'active' if opts.get('mode') == 'media' else '' }}" data-mode="media">Media</button>
            <button type="button" class="mode-btn {{ 'active' if opts.get('mode') == 'error' else '' }}" data-mode="error">Error</button>
          </div>
          <input type="hidden" class="host-mode" data-field="mode" value="{{ opts.get('mode', 'error') }}">
          <div class="panel host-panel host-panel-redirect {{ 'active' if opts.get('mode') == 'redirect' else '' }}">
            <label>Redirect URL</label>
            <input type="text" class="host-input" data-field="default_redirect_url" value="{{ opts.get('default_redirect_url', '') }}" placeholder="https://example.com">
          </div>
          <div class="panel host-panel host-panel-media {{ 'active' if opts.get('mode') == 'media' else '' }}">
            <label>Media URL or file</label>
            <input type="text" class="host-input" data-field="media_url" value="{{ opts.get('media_url', '') }}" placeholder="/media/... or URL">
            <label>From /media folder</label>
            <select class="host-media-file-select" aria-label="Select file from media folder">
              <option value="">— Select file (optional) —</option>
            </select>
            <label>Type</label>
            <select class="host-input host-select-type" data-field="media_type">
              <option value="image" {{ 'selected' if opts.get('media_type') == 'image' else '' }}>Image</option>
              <option value="gif" {{ 'selected' if opts.get('media_type') == 'gif' else '' }}>GIF</option>
              <option value="video" {{ 'selected' if opts.get('media_type') == 'video' else '' }}>Video</option>
              <option value="youtube" {{ 'selected' if opts.get('media_type') == 'youtube' else '' }}>YouTube</option>
            </select>
            <p class="section-label" style="margin-top:0.75rem;">Tab title</p>
            <select class="host-input host-tab-mode" data-field="media_tab_mode">
              <option value="none" {{ 'selected' if opts.get('media_tab_mode') == 'none' else '' }}>None</option>
              <option value="static" {{ 'selected' if opts.get('media_tab_mode') == 'static' else '' }}>Static</option>
              <option value="scrolling" {{ 'selected' if opts.get('media_tab_mode') == 'scrolling' else '' }}>Scrolling</option>
              <option value="rotating" {{ 'selected' if opts.get('media_tab_mode') == 'rotating' else '' }}>Rotating</option>
            </select>
            <div class="host-tab-panel host-tab-static {{ 'active' if opts.get('media_tab_mode') == 'static' else '' }}">
              <label>Static message</label>
              <input type="text" class="host-input" data-field="media_tab_static_text" value="{{ opts.get('media_tab_static_text', '') }}" placeholder="e.g. Loading..." maxlength="500">
            </div>
            <div class="host-tab-panel host-tab-scrolling {{ 'active' if opts.get('media_tab_mode') == 'scrolling' else '' }}">
              <label>Scrolling message</label>
              <input type="text" class="host-input" data-field="media_tab_scrolling_text" value="{{ opts.get('media_tab_scrolling_text', '') }}" placeholder="e.g. Please wait..." maxlength="500">
            </div>
            <div class="host-tab-panel host-tab-rotating {{ 'active' if opts.get('media_tab_mode') == 'rotating' else '' }}">
              <label>Rotating messages (one per line)</label>
              <textarea class="host-input" data-field="media_tab_rotating_messages" rows="2" placeholder="Message one&#10;Message two" maxlength="10000">{{ opts.get('media_tab_rotating_messages', '') }}</textarea>
              <label>Switch every (seconds)</label>
              <input type="number" class="host-input" data-field="media_tab_rotate_interval_sec" value="{{ opts.get('media_tab_rotate_interval_sec', 3) }}" min="1" max="60" style="width:5rem;">
            </div>
          </div>
          <div class="panel host-panel host-panel-error {{ 'active' if opts.get('mode') == 'error' else '' }}">
            <label>HTTP status</label>
            <select class="host-input" data-field="status_code">
              {% for code, label in status_options %}
              <option value="{{ code }}" {{ 'selected' if opts.get('status_code') == code else '' }}>{{ label }}</option>
              {% endfor %}
            </select>
          </div>
            </div>
            <script type="application/json" class="fa-initial">{{ opts | tojson }}</script>
          </div>
        </div>
        {% endfor %}
      </div>
      <div class="add-host-row">
        <input type="text" id="add-host-input" placeholder="e.g. trap.example.com" aria-label="New host name">
        <button type="button" id="add-host-btn">Add host</button>
        <span style="color: var(--muted);">or</span>
        <select id="add-host-detected" aria-label="Add from detected hosts">
          <option value="">— From detected —</option>
        </select>
        <button type="button" id="add-host-detected-btn">Add</button>
      </div>
      <p class="section-label">Hit notifications</p>
      <p class="hint" style="margin-top:0;">Filtered webhooks (Discord today). Use <strong>Immediately</strong> for server-side data only (IP, host, path, UA). Use <strong>After client capture</strong> when filtering on GPU or canvas fingerprint. Rules that require GPU/canvas are automatically switched to after capture when saved.</p>
      <p class="hint">When any rule is <strong>enabled</strong>, legacy <code>DISCORD_WEBHOOK_URL</code> / Telegram env alerts are not used (configure Discord via rules instead).</p>
      <div class="nr-panel" id="nr-panel">
        <div class="nr-toolbar">
          <div class="nr-toolbar-title">
            <span>Notification rules</span>
            <span id="nr-rule-count-badge" class="nr-badge" aria-live="polite">{{ notification_rules | length }}</span>
          </div>
          <button type="button" class="nr-btn-add nr-add-rule-btn" id="nr-add-btn">+ Add rule</button>
        </div>
        <p class="nr-summary-line" id="nr-summary-line"></p>
        <p class="hint" style="margin-top:0;font-size:0.78rem;">Rules persist in server config (<code>config.json</code>, key <code>notification_rules</code>) only after you click <strong>Save</strong> at the bottom of this page. You may define <strong>many</strong> rules — each appears as its own card below.</p>
        <script type="application/json" id="nr-initial">{{ notification_rules | tojson }}</script>
        <div id="nr-empty-state" class="nr-empty{% if not notification_rules %} visible{% endif %}" role="status">No rules in this list yet. Click <strong>+ Add rule</strong> to create one. Multiple rules are supported (e.g. separate Discord channels). Changes are not stored until you press <strong>Save</strong> at the bottom of the page.</div>
        <div id="notification-rules-container" class="nr-rules-list" role="list" aria-label="Notification rules"></div>
        <p class="nr-save-reminder">Editing or deleting cards here is temporary until you submit the form with the main <strong>Save</strong> button below.</p>
      </div>
      <input type="hidden" name="notification_rules_json" id="notification-rules-json" value="">
      <div id="notification-rule-template" style="display:none;" class="nr-block" role="listitem">
        <div class="nr-block-top">
          <div class="nr-title-stack">
            <div class="nr-rule-line">
              <span class="nr-rule-number">Rule 1</span>
              <span class="nr-rule-display-title">Untitled rule</span>
              <span class="nr-status-badge nr-status-on">Enabled</span>
            </div>
            <p class="hint" style="margin:0;font-size:0.72rem;line-height:1.4;">Edit this card, then press <strong>Save</strong> at the bottom of the settings page to keep changes.</p>
          </div>
          <button type="button" class="nr-btn-danger nr-remove" aria-label="Delete this notification rule">Delete rule</button>
        </div>
        <div class="nr-block-header">
          <label style="margin:0;display:flex;align-items:center;gap:0.5rem;color:var(--text);"><input type="checkbox" class="nr-enabled" checked> <span>Rule enabled (fire webhook when filters match)</span></label>
        </div>
        <div class="nr-grid">
          <div class="nr-grid-full">
            <label>Rule name (optional)</label>
            <input type="text" class="nr-name" placeholder="e.g. GPU hits only" maxlength="120">
          </div>
          <div>
            <label>When to notify</label>
            <select class="nr-trigger">
              <option value="immediate">Immediately (on hit)</option>
              <option value="after_capture">After client capture</option>
            </select>
          </div>
          <div>
            <label>Discord webhook URL</label>
            <input type="text" class="nr-webhook-url" placeholder="https://discord.com/api/webhooks/..." autocomplete="off" spellcheck="false">
          </div>
          <div class="nr-grid-full">
            <label>Hosts (comma-separated; empty = any)</label>
            <input type="text" class="nr-hosts" placeholder="trap.example.com, example.com">
          </div>
          <div class="nr-grid-full">
            <label>Path contains (optional)</label>
            <input type="text" class="nr-path-contains" placeholder="substring of path" maxlength="500">
          </div>
          <div class="nr-grid-full">
            <label>Tracked link IDs (comma-separated; empty = any)</label>
            <input type="text" class="nr-link-ids" placeholder="Numeric IDs from the Links page, e.g. 4, 12">
          </div>
          <div class="nr-grid-full">
            <label>Tracked link tokens (comma-separated; empty = any)</label>
            <input type="text" class="nr-link-tokens" placeholder="/l/abc123 or abc123 — Grabify-style /l/ URLs">
          </div>
          <div>
            <label>GPU (WebGL renderer)</label>
            <select class="nr-gpu">
              <option value="any">Any</option>
              <option value="yes">Present (likely browser)</option>
              <option value="no">Absent</option>
            </select>
          </div>
          <div>
            <label>Canvas fingerprint</label>
            <select class="nr-canvas">
              <option value="any">Any</option>
              <option value="yes">Present</option>
              <option value="no">Absent</option>
            </select>
          </div>
          <div>
            <label>Mention users (Discord IDs, comma-separated)</label>
            <input type="text" class="nr-mention-users" placeholder="leave empty for no ping">
          </div>
          <div>
            <label>Mention roles (role IDs, comma-separated)</label>
            <input type="text" class="nr-mention-roles" placeholder="optional">
          </div>
          <div class="nr-grid-full">
            <label>Webhook display name (optional)</label>
            <input type="text" class="nr-username" placeholder="Honeytoken" maxlength="80">
          </div>
          <div class="nr-grid-full nr-test-row">
            <div style="display:flex;flex-wrap:wrap;align-items:center;gap:0.65rem;">
              <button type="button" class="nr-btn-test nr-test-send">Send test notification</button>
              <span class="nr-test-status hint" style="margin:0;" aria-live="polite"></span>
            </div>
            <p class="hint" style="margin:0.35rem 0 0;font-size:0.72rem;line-height:1.45;">Posts one fictional hit (documented TEST-NET IP, sample GPU/canvas) to Discord using this card’s webhook and mention settings. Save is not required first.</p>
          </div>
        </div>
      </div>
      <input type="hidden" name="host_settings_json" id="host-settings-json" value="">
      <button type="submit">Save</button>
      {% if saved %}<p class="saved">Saved — notification rules, host overrides, and other settings written to server config.</p>{% endif %}
    </form>
    <div id="host-block-template" style="display:none;" class="host-block" data-host="">
      <div class="host-block-header">
        <span class="host-name"></span>
        <button type="button" class="host-remove" aria-label="Remove host">Remove</button>
      </div>
      <div class="fa-scope host-fa-scope">
        <div class="fa-random-row">
          <label><input type="checkbox" class="fa-random-toggle"> Randomize final action</label>
        </div>
        <div class="fa-multi-wrap" hidden>
          <div class="fa-toolbar">
            <span>Actions</span>
            <span class="fa-count-badge" aria-live="polite">0</span>
            <button type="button" class="fa-btn-add">+ Add action</button>
            <button type="button" class="fa-btn-clear">Clear all</button>
          </div>
          <div class="fa-empty visible">No actions in list.</div>
          <div class="fa-actions-list"></div>
        </div>
        <div class="fa-single-wrap">
      <div class="mode-toggles host-mode-toggles" role="group">
        <button type="button" class="mode-btn" data-mode="redirect">Redirect</button>
        <button type="button" class="mode-btn" data-mode="media">Media</button>
        <button type="button" class="mode-btn active" data-mode="error">Error</button>
      </div>
      <input type="hidden" class="host-mode" data-field="mode" value="error">
      <div class="panel host-panel host-panel-redirect">
        <label>Redirect URL</label>
        <input type="text" class="host-input" data-field="default_redirect_url" value="" placeholder="https://example.com">
      </div>
      <div class="panel host-panel host-panel-media">
        <label>Media URL or file</label>
        <input type="text" class="host-input" data-field="media_url" value="" placeholder="/media/... or URL">
        <label>From /media folder</label>
        <select class="host-media-file-select" aria-label="Select file from media folder">
          <option value="">— Select file (optional) —</option>
        </select>
        <label>Type</label>
        <select class="host-input host-select-type" data-field="media_type">
          <option value="image">Image</option>
          <option value="gif">GIF</option>
          <option value="video" selected>Video</option>
          <option value="youtube">YouTube</option>
        </select>
        <p class="section-label" style="margin-top:0.75rem;">Tab title</p>
        <select class="host-input host-tab-mode" data-field="media_tab_mode">
          <option value="none" selected>None</option>
          <option value="static">Static</option>
          <option value="scrolling">Scrolling</option>
          <option value="rotating">Rotating</option>
        </select>
        <div class="host-tab-panel host-tab-static">
          <label>Static message</label>
          <input type="text" class="host-input" data-field="media_tab_static_text" value="" placeholder="e.g. Loading..." maxlength="500">
        </div>
        <div class="host-tab-panel host-tab-scrolling">
          <label>Scrolling message</label>
          <input type="text" class="host-input" data-field="media_tab_scrolling_text" value="" placeholder="e.g. Please wait..." maxlength="500">
        </div>
        <div class="host-tab-panel host-tab-rotating">
          <label>Rotating messages (one per line)</label>
          <textarea class="host-input" data-field="media_tab_rotating_messages" rows="2" placeholder="Message one&#10;Message two" maxlength="10000"></textarea>
          <label>Switch every (seconds)</label>
          <input type="number" class="host-input" data-field="media_tab_rotate_interval_sec" value="3" min="1" max="60" style="width:5rem;">
        </div>
      </div>
      <div class="panel host-panel host-panel-error active">
        <label>HTTP status</label>
        <select class="host-input" data-field="status_code">
          {% for code, label in status_options %}
          <option value="{{ code }}" {{ 'selected' if code == 404 else '' }}>{{ label }}</option>
          {% endfor %}
        </select>
      </div>
        </div>
        <script type="application/json" class="fa-initial">{}</script>
      </div>
    </div>
    {{ final_action_template | safe }}
  </div>
  <script>
    {{ final_actions_js | safe }}
    var form = document.getElementById('settings-form');
    var modeInput = document.getElementById('mode-input');
    var panelRedirect = document.getElementById('panel-redirect');
    var panelMedia = document.getElementById('panel-media');
    var panelError = document.getElementById('panel-error');
    document.querySelectorAll('.mode-toggles:not(.host-mode-toggles) .mode-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var m = this.getAttribute('data-mode');
        btn.closest('.wrap').querySelectorAll('.mode-toggles:not(.host-mode-toggles) .mode-btn').forEach(function(b) { b.classList.remove('active'); });
        this.classList.add('active');
        modeInput.value = m;
        panelRedirect.classList.toggle('active', m === 'redirect');
        panelMedia.classList.toggle('active', m === 'media');
        panelError.classList.toggle('active', m === 'error');
      });
    });
    var mediaUrlInput = document.getElementById('media_url');
    var mediaFileSelect = document.getElementById('media_file_select');
    if (mediaFileSelect) {
      fetch('/api/media-files', { credentials: 'same-origin' }).then(function(r) { return r.json(); }).then(function(files) {
        files.forEach(function(f) {
          var opt = document.createElement('option');
          opt.value = '/media/' + f;
          opt.textContent = f;
          mediaFileSelect.appendChild(opt);
        });
      }).catch(function() {});
      mediaFileSelect.addEventListener('change', function() {
        if (this.value) mediaUrlInput.value = this.value;
      });
    }
    var mediaTabModeSelect = document.getElementById('media_tab_mode');
    if (mediaTabModeSelect) {
      mediaTabModeSelect.addEventListener('change', function() {
        var v = this.value;
        document.querySelectorAll('.panel-media .media-tab-panel').forEach(function(p) {
          p.classList.remove('active');
          if (p.classList.contains('media-tab-' + v)) p.classList.add('active');
        });
      });
    }
    var mediaFilesList = [];
    fetch('/api/media-files', { credentials: 'same-origin' }).then(function(r) { return r.json(); }).then(function(files) {
      mediaFilesList = files || [];
      document.querySelectorAll('#host-blocks-container .host-media-file-select').forEach(function(sel) { populateOneHostMediaSelect(sel); });
    }).catch(function() {});
    function populateOneHostMediaSelect(selectEl) {
      if (!selectEl) return;
      var block = selectEl.closest('.host-block');
      var input = block ? block.querySelector('input[data-field="media_url"]') : null;
      while (selectEl.options.length > 1) selectEl.remove(1);
      (mediaFilesList || []).forEach(function(f) {
        var opt = document.createElement('option');
        opt.value = '/media/' + f;
        opt.textContent = f;
        selectEl.appendChild(opt);
      });
      if (input && input.value && input.value.indexOf('/media/') === 0) selectEl.value = input.value;
      if (!selectEl.dataset.bound) {
        selectEl.dataset.bound = '1';
        selectEl.addEventListener('change', function() {
          if (this.value && input) input.value = this.value;
        });
      }
    }
    function bindHostBlock(block) {
      var toggles = block.querySelectorAll('.host-mode-toggles .mode-btn');
      var modeInput = block.querySelector('.host-mode[data-field="mode"]');
      var panels = { redirect: block.querySelector('.host-panel-redirect'), media: block.querySelector('.host-panel-media'), error: block.querySelector('.host-panel-error') };
      toggles.forEach(function(btn) {
        btn.addEventListener('click', function() {
          var m = this.getAttribute('data-mode');
          toggles.forEach(function(b) { b.classList.remove('active'); });
          this.classList.add('active');
          modeInput.value = m;
          panels.redirect.classList.toggle('active', m === 'redirect');
          panels.media.classList.toggle('active', m === 'media');
          panels.error.classList.toggle('active', m === 'error');
        });
      });
      block.querySelector('.host-remove').addEventListener('click', function() { block.remove(); });
      var faScope = block.querySelector('.host-fa-scope');
      if (faScope && typeof initFinalActionsScope === 'function') {
        var boot = faScope.querySelector('.fa-initial');
        var initial = {};
        if (boot && boot.textContent) {
          try { initial = JSON.parse(boot.textContent); } catch (e1) { initial = {}; }
        }
        initFinalActionsScope(faScope, initial);
      }
      var tabModeSelect = block.querySelector('.host-tab-mode');
      if (tabModeSelect) {
        tabModeSelect.addEventListener('change', function() {
          var v = this.value;
          block.querySelectorAll('.host-tab-panel').forEach(function(p) {
            p.classList.remove('active');
            if (p.classList.contains('host-tab-' + v)) p.classList.add('active');
          });
        });
      }
    }
    document.querySelectorAll('#host-blocks-container .host-block').forEach(bindHostBlock);
    document.getElementById('add-host-btn').addEventListener('click', function() {
      var input = document.getElementById('add-host-input');
      var host = (input.value || '').trim().toLowerCase();
      if (!host) return;
      if (document.querySelector('.host-block[data-host="' + host.replace(/"/g, '&quot;') + '"]')) return;
      var tpl = document.getElementById('host-block-template');
      var clone = tpl.cloneNode(true);
      clone.removeAttribute('id');
      clone.style.display = '';
      clone.setAttribute('data-host', host);
      clone.querySelector('.host-name').textContent = host;
      document.getElementById('host-blocks-container').appendChild(clone);
      bindHostBlock(clone);
      populateOneHostMediaSelect(clone.querySelector('.host-media-file-select'));
      input.value = '';
    });
    var detectedSelect = document.getElementById('add-host-detected');
    var addDetectedBtn = document.getElementById('add-host-detected-btn');
    fetch('/api/distinct-hosts', { credentials: 'same-origin' }).then(function(r) { return r.json(); }).then(function(hosts) {
      hosts.forEach(function(h) {
        if (!h || !h.trim()) return;
        var opt = document.createElement('option');
        opt.value = h.trim();
        opt.textContent = h.trim();
        detectedSelect.appendChild(opt);
      });
    }).catch(function() {});
    addDetectedBtn.addEventListener('click', function() {
      var host = (detectedSelect.value || '').trim().toLowerCase();
      if (!host) return;
      if (document.querySelector('.host-block[data-host="' + host.replace(/"/g, '&quot;') + '"]')) return;
      var tpl = document.getElementById('host-block-template');
      var clone = tpl.cloneNode(true);
      clone.removeAttribute('id');
      clone.style.display = '';
      clone.setAttribute('data-host', host);
      clone.querySelector('.host-name').textContent = host;
      document.getElementById('host-blocks-container').appendChild(clone);
      bindHostBlock(clone);
      populateOneHostMediaSelect(clone.querySelector('.host-media-file-select'));
      detectedSelect.value = '';
    });
    function serializeNrBlock(block) {
      function nrSplitComma(s) {
        return (s || '').split(/[,\\n]+/).map(function(x) { return x.trim(); }).filter(Boolean);
      }
      function nrSplitInts(s) {
        var out = [];
        nrSplitComma(s).forEach(function(p) {
          var n = parseInt(p, 10);
          if (!isNaN(n) && n > 0) out.push(n);
        });
        return out;
      }
      function nrSplitSnowflakes(s) {
        var out = [];
        nrSplitComma(s).forEach(function(p) {
          if (/^\\d{17,22}$/.test(p)) out.push(p);
        });
        return out;
      }
      var rid = (block.getAttribute('data-nr-id') || '').trim();
      if (!rid) {
        if (window.crypto && crypto.getRandomValues) {
          var ab = new Uint8Array(8);
          crypto.getRandomValues(ab);
          rid = Array.from(ab).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
        } else {
          rid = 'nr' + Math.random().toString(16).slice(2);
        }
        block.setAttribute('data-nr-id', rid);
      }
      return {
        id: rid,
        enabled: block.querySelector('.nr-enabled').checked,
        name: (block.querySelector('.nr-name').value || '').trim(),
        trigger: block.querySelector('.nr-trigger').value,
        filters: {
          hosts: nrSplitComma(block.querySelector('.nr-hosts').value).map(function(h) { return h.toLowerCase(); }),
          path_contains: (block.querySelector('.nr-path-contains').value || '').trim(),
          link_ids: nrSplitInts(block.querySelector('.nr-link-ids').value),
          link_tokens: nrSplitComma(block.querySelector('.nr-link-tokens').value).map(function(t) {
            t = t.trim();
            var low = t.toLowerCase();
            var idx = low.lastIndexOf('/l/');
            if (idx >= 0) t = t.slice(idx + 3);
            return t.replace(/^[/]+/, '').split('?')[0].split('#')[0].trim();
          }).filter(Boolean),
          gpu: block.querySelector('.nr-gpu').value,
          canvas: block.querySelector('.nr-canvas').value
        },
        channel: {
          type: 'discord_webhook',
          webhook_url: (block.querySelector('.nr-webhook-url').value || '').trim(),
          mention_user_ids: nrSplitSnowflakes(block.querySelector('.nr-mention-users').value),
          mention_role_ids: nrSplitSnowflakes(block.querySelector('.nr-mention-roles').value),
          username: (block.querySelector('.nr-username').value || '').trim()
        }
      };
    }
    (function initNotificationRules() {
      var boot = document.getElementById('nr-initial');
      var container = document.getElementById('notification-rules-container');
      var tpl = document.getElementById('notification-rule-template');
      var addBtn = document.getElementById('nr-add-btn');
      if (!container || !tpl || !addBtn) return;
      function nrRandomId() {
        if (window.crypto && crypto.getRandomValues) {
          var a = new Uint8Array(8);
          crypto.getRandomValues(a);
          return Array.from(a).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
        }
        return 'nr' + Math.random().toString(16).slice(2);
      }
      function nrRenumber() {
        container.querySelectorAll('.nr-block').forEach(function(block, i) {
          var numEl = block.querySelector('.nr-rule-number');
          if (numEl) numEl.textContent = 'Rule ' + (i + 1);
        });
      }
      function nrRefreshChrome() {
        var n = container.querySelectorAll('.nr-block').length;
        var badge = document.getElementById('nr-rule-count-badge');
        var empty = document.getElementById('nr-empty-state');
        var summary = document.getElementById('nr-summary-line');
        if (badge) badge.textContent = String(n);
        if (empty) empty.classList.toggle('visible', n === 0);
        if (summary) {
          if (n === 0) {
            summary.textContent = 'No rules in the list. Add one or more cards below — multiple Discord destinations are supported.';
          } else if (n === 1) {
            summary.textContent = '1 rule below. Need another channel? Click + Add rule again.';
          } else {
            summary.textContent = n + ' rules below; each is separate (own webhook and filters).';
          }
        }
      }
      function bindNrRemove(block) {
        var rm = block.querySelector('.nr-remove');
        if (rm) rm.addEventListener('click', function() {
          if (!window.confirm('Delete this notification rule from the list? Click Save at the bottom of the page to persist.')) return;
          block.remove();
          nrRenumber();
          nrRefreshChrome();
        });
      }
      function bindNrBlock(block) {
        function syncChrome() {
          var nameEl = block.querySelector('.nr-name');
          var disp = block.querySelector('.nr-rule-display-title');
          var en = block.querySelector('.nr-enabled');
          var badge = block.querySelector('.nr-status-badge');
          var nm = (nameEl && nameEl.value || '').trim();
          if (disp) disp.textContent = nm || 'Untitled rule';
          if (badge && en) {
            badge.textContent = en.checked ? 'Enabled' : 'Disabled';
            badge.className = 'nr-status-badge ' + (en.checked ? 'nr-status-on' : 'nr-status-off');
          }
        }
        var nameEl = block.querySelector('.nr-name');
        var en = block.querySelector('.nr-enabled');
        if (nameEl) nameEl.addEventListener('input', syncChrome);
        if (en) en.addEventListener('change', syncChrome);
        syncChrome();
        bindNrRemove(block);
        var testBtn = block.querySelector('.nr-test-send');
        var statusEl = block.querySelector('.nr-test-status');
        if (testBtn && statusEl) {
          testBtn.addEventListener('click', function() {
            var payload = serializeNrBlock(block);
            if (!payload) {
              statusEl.textContent = 'Could not read rule.';
              return;
            }
            statusEl.textContent = '';
            testBtn.disabled = true;
            fetch('/api/notification-rule-test', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
              body: JSON.stringify({ rule_snapshot: payload })
            }).then(function(r) {
              return r.json().catch(function() { return {}; }).then(function(j) { return { ok: r.ok, status: r.status, j: j }; });
            }).then(function(x) {
              testBtn.disabled = false;
              if (x.j && x.j.ok) {
                statusEl.textContent = 'Sent — check Discord.';
              } else {
                statusEl.textContent = (x.j && x.j.message) ? x.j.message : 'Failed.';
                if (x.status === 429) statusEl.textContent += ' (wait a few seconds)';
              }
            }).catch(function() {
              testBtn.disabled = false;
              statusEl.textContent = 'Network error.';
            });
          });
        }
      }      function fillNrBlock(block, rule) {
        rule = rule || {};
        var ch = rule.channel || {};
        if (ch.config && typeof ch.config === 'object' && ch.type && ch.type !== 'discord_webhook') {
          ch = ch.config;
        }
        var fl = rule.filters || {};
        block.setAttribute('data-nr-id', rule.id || '');
        var en = block.querySelector('.nr-enabled');
        if (en) en.checked = rule.enabled !== false;
        var nm = block.querySelector('.nr-name');
        if (nm) nm.value = rule.name || '';
        var tr = block.querySelector('.nr-trigger');
        if (tr) tr.value = rule.trigger === 'after_capture' ? 'after_capture' : 'immediate';
        var hosts = block.querySelector('.nr-hosts');
        if (hosts) hosts.value = Array.isArray(fl.hosts) ? fl.hosts.join(', ') : '';
        var pc = block.querySelector('.nr-path-contains');
        if (pc) pc.value = fl.path_contains || '';
        var lids = block.querySelector('.nr-link-ids');
        if (lids) lids.value = Array.isArray(fl.link_ids) ? fl.link_ids.join(', ') : '';
        var ltoks = block.querySelector('.nr-link-tokens');
        if (ltoks) ltoks.value = Array.isArray(fl.link_tokens) ? fl.link_tokens.join(', ') : '';
        var gpu = block.querySelector('.nr-gpu');
        if (gpu) {
          var gv = fl.gpu || 'any';
          gpu.value = (gv === 'yes' || gv === 'no') ? gv : 'any';
        }
        var cv = block.querySelector('.nr-canvas');
        if (cv) {
          var cx = fl.canvas || 'any';
          cv.value = (cx === 'yes' || cx === 'no') ? cx : 'any';
        }
        var wh = block.querySelector('.nr-webhook-url');
        if (wh) wh.value = ch.webhook_url || '';
        var mu = block.querySelector('.nr-mention-users');
        if (mu) mu.value = Array.isArray(ch.mention_user_ids) ? ch.mention_user_ids.join(', ') : '';
        var mr = block.querySelector('.nr-mention-roles');
        if (mr) mr.value = Array.isArray(ch.mention_role_ids) ? ch.mention_role_ids.join(', ') : '';
        var un = block.querySelector('.nr-username');
        if (un) un.value = ch.username || '';
      }
      function appendRule(rule) {
        var clone = tpl.cloneNode(true);
        clone.removeAttribute('id');
        clone.style.display = '';
        fillNrBlock(clone, rule);
        if (!(clone.getAttribute('data-nr-id') || '').trim()) {
          clone.setAttribute('data-nr-id', nrRandomId());
        }
        container.appendChild(clone);
        bindNrBlock(clone);
        nrRenumber();
        nrRefreshChrome();
      }
      var initial = [];
      if (boot && boot.textContent) {
        try { initial = JSON.parse(boot.textContent); } catch (e1) { initial = []; }
      }
      if (!Array.isArray(initial)) initial = [];
      initial.forEach(appendRule);
      nrRefreshChrome();
      addBtn.addEventListener('click', function() {
        appendRule({ enabled: true, trigger: 'immediate', filters: {}, channel: { type: 'discord_webhook' } });
      });
    })();
    (function initDefaultFinalActions() {
      var scope = document.getElementById('default-fa-scope');
      var boot = document.getElementById('fa-default-initial');
      if (!scope || typeof initFinalActionsScope !== 'function') return;
      var initial = {};
      if (boot && boot.textContent) {
        try { initial = JSON.parse(boot.textContent); } catch (e2) { initial = {}; }
      }
      initFinalActionsScope(scope, initial);
    })();
    form.addEventListener('submit', function() {
      var defaultScope = document.getElementById('default-fa-scope');
      if (defaultScope && typeof serializeFinalActionsScope === 'function') {
        document.getElementById('action-settings-json').value = JSON.stringify(serializeFinalActionsScope(defaultScope));
      }
      var obj = {};
      document.querySelectorAll('#host-blocks-container .host-block').forEach(function(block) {
        var host = (block.getAttribute('data-host') || '').trim().toLowerCase();
        if (!host) return;
        var faScope = block.querySelector('.host-fa-scope');
        if (faScope && typeof serializeFinalActionsScope === 'function') {
          obj[host] = serializeFinalActionsScope(faScope);
          return;
        }
        var modeEl = block.querySelector('.host-mode[data-field="mode"]');
        var mode = (modeEl && modeEl.value) || 'error';
        var get = function(f) {
          var el = block.querySelector('[data-field="' + f + '"]');
          return el ? (el.value || '').trim() : '';
        };
        var tabInterval = parseInt(get('media_tab_rotate_interval_sec') || '3', 10);
        if (isNaN(tabInterval) || tabInterval < 1) tabInterval = 3;
        if (tabInterval > 60) tabInterval = 60;
        obj[host] = {
          mode: mode,
          default_redirect_url: get('default_redirect_url'),
          media_url: get('media_url'),
          media_type: get('media_type'),
          media_tab_mode: get('media_tab_mode') || 'none',
          media_tab_static_text: get('media_tab_static_text'),
          media_tab_scrolling_text: get('media_tab_scrolling_text'),
          media_tab_rotating_messages: get('media_tab_rotating_messages'),
          media_tab_rotate_interval_sec: tabInterval,
          status_code: parseInt(get('status_code') || '404', 10) || 404,
          random_actions_enabled: false,
          actions: []
        };
      });
      document.getElementById('host-settings-json').value = JSON.stringify(obj);
      var nrRules = [];
      document.querySelectorAll('#notification-rules-container .nr-block').forEach(function(block) {
        nrRules.push(serializeNrBlock(block));
      });
      document.getElementById('notification-rules-json').value = JSON.stringify(nrRules);
    });
  </script>
</body>
</html>
"""


NGINX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nginx config – Honeytoken Admin</title>
  <style>
    :root { --bg: #0a0a0b; --surface: #141416; --border: #27272a; --muted: #71717a; --text: #fafafa; --accent: #3b82f6; }
    * { box-sizing: border-box; }
    body { font-family: ui-monospace, monospace; margin: 0; padding: 0; background: var(--bg); color: var(--text); min-height: 100vh; font-size: 0.8125rem; }
    .wrap { max-width: 720px; margin: 0 auto; padding: 1.5rem; }
    h1 { font-size: 1.1rem; font-family: ui-sans-serif, system-ui, sans-serif; margin-bottom: 0.5rem; }
    .meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 1rem; font-family: ui-sans-serif, system-ui, sans-serif; }
    a { color: var(--accent); text-decoration: none; font-family: ui-sans-serif, system-ui, sans-serif; }
    a:hover { text-decoration: underline; }
    .intro { color: var(--muted); font-size: 0.8rem; margin-bottom: 1rem; font-family: ui-sans-serif, system-ui, sans-serif; line-height: 1.5; }
    pre { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; overflow-x: auto; white-space: pre; margin: 0; }
    .copy { margin-top: 1rem; font-family: ui-sans-serif, system-ui, sans-serif; }
    .copy button { padding: 0.4rem 0.75rem; background: var(--accent); color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
    .copy button:hover { background: #2563eb; }
    .copy-done { color: #22c55e; font-size: 0.8rem; margin-left: 0.5rem; }
    @media (max-width: 760px) {
      .wrap { max-width: 100%; padding: 0.85rem; overflow-x: hidden; }
      h1 { font-size: 1rem; line-height: 1.35; }
      .meta, .intro { line-height: 1.6; }
      pre { max-width: 100%; padding: 0.85rem; font-size: 0.78rem; -webkit-overflow-scrolling: touch; }
      .copy button { width: 100%; min-height: 2.5rem; font-size: 1rem; }
      .copy-done { display: block; margin: 0.5rem 0 0; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Custom Nginx configuration (npmplus)</h1>
    <p class="meta"><a href="/">← Dashboard</a> · <a href="/links">Links</a> · <a href="/settings">Settings</a></p>
    <p class="intro">Paste this into your Nginx Proxy Manager (or npmplus) <strong>Custom / Advanced</strong> configuration for the proxy host that serves the trap. NPM injects these directives into its location block — you do <strong>not</strong> need the outer <code>location / {{ '{' }}</code> wrapper. The <code>proxy_set_header</code> lines are required so the trap logs real visitor IPs instead of your server's LAN address.</p>
    <pre id="nginx-config">{{ nginx_config }}</pre>
    <div class="copy">
      <button type="button" id="copy-btn">Copy</button>
      <span class="copy-done" id="copy-done" style="display:none;">Copied.</span>
    </div>
  </div>
  <script>
    document.getElementById('copy-btn').addEventListener('click', function() {
      var pre = document.getElementById('nginx-config');
      navigator.clipboard.writeText(pre.textContent).then(function() {
        var d = document.getElementById('copy-done');
        d.style.display = 'inline';
        setTimeout(function() { d.style.display = 'none'; }, 2000);
      });
    });
  </script>
</body>
</html>
"""


def _parse_filters():
    """Build filter dict from request.args; validated and safe for store."""
    from store import FILTER_LOCATION_MAX_LEN, FILTER_PATH_MAX_LEN, FILTER_HOST_MAX_ITEMS, FILTER_HOST_MAX_LEN, FILTER_VISITOR_FP_MAX_LEN
    from visitor_fingerprint import visitor_fp_filter_token
    filters = {}
    gpu = (request.args.get("gpu") or "").strip().lower()
    if gpu in ("yes", "y", "1", "true"):
        filters["gpu_detected"] = True
    elif gpu in ("no", "n", "0", "false"):
        filters["gpu_detected"] = False
    fp = (request.args.get("fingerprint") or "").strip().lower()
    if fp in ("yes", "y", "1", "true"):
        filters["fingerprint_detected"] = True
    elif fp in ("no", "n", "0", "false"):
        filters["fingerprint_detected"] = False
    visitor_raw = (request.args.get("visitor_fp") or "").strip()
    if visitor_raw:
        token = visitor_fp_filter_token(visitor_raw[:FILTER_VISITOR_FP_MAX_LEN])
        if token:
            filters["visitor_fp_id"] = token
            if (request.args.get("sort_visitor") or "1").strip().lower() in ("1", "yes", "true", "on"):
                filters["sort_by_visitor_fp"] = True
    repeat = (request.args.get("repeat") or "").strip().lower()
    if repeat in ("yes", "y", "1", "true"):
        filters["repeat_visitor"] = True
    loc = (request.args.get("location") or "").strip()
    if loc:
        filters["location_substring"] = loc[:FILTER_LOCATION_MAX_LEN]
    path_q = (request.args.get("path") or "").strip()
    if path_q:
        filters["path_substring"] = path_q[:FILTER_PATH_MAX_LEN]
    hosts = request.args.getlist("host")
    if hosts:
        hosts = [h.strip()[:FILTER_HOST_MAX_LEN] for h in hosts if h and h.strip()][:FILTER_HOST_MAX_ITEMS]
        if hosts:
            filters["host_in"] = hosts
    link_id = request.args.get("link", type=int)
    if link_id is not None and link_id >= 1:
        filters["link_id"] = link_id
    return filters


def _parse_filters_from_form(form):
    """Build filter dict from form (e.g. return_* after delete); same shape as _parse_filters()."""
    from store import FILTER_LOCATION_MAX_LEN, FILTER_PATH_MAX_LEN, FILTER_HOST_MAX_ITEMS, FILTER_HOST_MAX_LEN, FILTER_VISITOR_FP_MAX_LEN
    from visitor_fingerprint import visitor_fp_filter_token
    filters = {}
    gpu = (form.get("return_gpu") or "").strip().lower()
    if gpu in ("yes", "y", "1", "true"):
        filters["gpu_detected"] = True
    elif gpu in ("no", "n", "0", "false"):
        filters["gpu_detected"] = False
    fp = (form.get("return_fingerprint") or "").strip().lower()
    if fp in ("yes", "y", "1", "true"):
        filters["fingerprint_detected"] = True
    elif fp in ("no", "n", "0", "false"):
        filters["fingerprint_detected"] = False
    visitor_raw = (form.get("return_visitor_fp") or "").strip()
    if visitor_raw:
        token = visitor_fp_filter_token(visitor_raw[:FILTER_VISITOR_FP_MAX_LEN])
        if token:
            filters["visitor_fp_id"] = token
            filters["sort_by_visitor_fp"] = True
    repeat = (form.get("return_repeat") or "").strip().lower()
    if repeat in ("yes", "y", "1", "true"):
        filters["repeat_visitor"] = True
    loc = (form.get("return_location") or "").strip()
    if loc:
        filters["location_substring"] = loc[:FILTER_LOCATION_MAX_LEN]
    path_q = (form.get("return_path") or "").strip()
    if path_q:
        filters["path_substring"] = path_q[:FILTER_PATH_MAX_LEN]
    hosts = form.getlist("return_host")
    if hosts:
        hosts = [h.strip()[:FILTER_HOST_MAX_LEN] for h in hosts if h and str(h).strip()][:FILTER_HOST_MAX_ITEMS]
        if hosts:
            filters["host_in"] = hosts
    link_id = form.get("return_link", type=int)
    if link_id is not None and link_id >= 1:
        filters["link_id"] = link_id
    return filters


def _filter_query_string(gpu=None, fingerprint=None, location=None, path=None, hosts=None, link=None, visitor_fp=None, repeat=None, sort_visitor=None):
    """Build query string for filter params (for pagination links)."""
    from urllib.parse import urlencode
    params = []
    if gpu is not None and gpu != "":
        params.append(("gpu", gpu))
    if fingerprint is not None and fingerprint != "":
        params.append(("fingerprint", fingerprint))
    if visitor_fp is not None and visitor_fp != "":
        params.append(("visitor_fp", visitor_fp))
        if sort_visitor:
            params.append(("sort_visitor", "1"))
    if repeat is not None and repeat != "":
        params.append(("repeat", repeat))
    if location is not None and location != "":
        params.append(("location", location))
    if path is not None and path != "":
        params.append(("path", path))
    if hosts:
        for h in hosts:
            params.append(("host", h))
    if link is not None and link != "":
        params.append(("link", link))
    return ("&" + urlencode(params)) if params else ""


@app.route("/")
@_auth_required
def dashboard():
    per_page = 100
    try:
        requested = request.args.get("per_page", type=int)
        if requested is not None and requested in PER_PAGE_OPTIONS:
            per_page = requested
    except (ValueError, TypeError):
        pass
    page = 1
    try:
        requested = request.args.get("page", type=int)
        if requested is not None and requested >= 1:
            page = requested
    except (ValueError, TypeError):
        pass
    filters = _parse_filters()
    total_count = get_hits_count(filters)
    total_pages = max(1, (total_count + per_page - 1) // per_page) if total_count else 1
    page = min(page, total_pages)
    offset = (page - 1) * per_page
    hits = get_hits(limit=per_page, offset=offset, filters=filters)
    page_geo_points = []
    for h in hits:
        lat, lng = h.get("latitude"), h.get("longitude")
        if lat is not None and lng is not None:
            try:
                page_geo_points.append({
                    "lat": float(lat),
                    "lng": float(lng),
                    "weight": 1,
                    "hit_id": int(h.get("_id")),
                })
            except (TypeError, ValueError):
                pass
    try:
        deleted = request.args.get("deleted", type=int)
    except (ValueError, TypeError):
        deleted = None
    cfg = get_config()
    display_tz = (cfg.get("timezone") or DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE
    filter_gpu = request.args.get("gpu", "")
    filter_fingerprint = request.args.get("fingerprint", "")
    filter_location = request.args.get("location", "")
    filter_path = request.args.get("path", "")
    filter_hosts = request.args.getlist("host")
    filter_link = request.args.get("link", "")
    filter_visitor_fp = request.args.get("visitor_fp", "")
    filter_repeat = request.args.get("repeat", "")
    distinct_hosts = get_distinct_hosts()
    tracked_links = list_tracked_links(sort="newest", limit=1000)
    tracked_links_by_id = {link["_id"]: link for link in tracked_links}
    filter_query_string = _filter_query_string(
        filter_gpu, filter_fingerprint, filter_location, filter_path, filter_hosts, filter_link,
        visitor_fp=filter_visitor_fp or None,
        repeat=filter_repeat or None,
        sort_visitor=bool(filters.get("sort_by_visitor_fp")),
    )
    return render_template_string(
        DASHBOARD_HTML,
        hits=hits,
        count=total_count,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        per_page_options=PER_PAGE_OPTIONS,
        page_geo_points=page_geo_points,
        domain=ROOT_DOMAIN,
        timezone=display_tz,
        location_str=_location_str,
        gpu_str=_gpu_str,
        fingerprint_str=_fingerprint_str,
        visitor_display=_visitor_display,
        host_display=_host_display,
        format_ts_readable=_format_ts_readable,
        deleted=deleted,
        filter_gpu=filter_gpu,
        filter_fingerprint=filter_fingerprint,
        filter_visitor_fp=filter_visitor_fp,
        filter_repeat=filter_repeat,
        filter_location=filter_location,
        filter_path=filter_path,
        filter_hosts=filter_hosts,
        filter_link=filter_link,
        distinct_hosts=distinct_hosts,
        tracked_links=tracked_links,
        tracked_links_by_id=tracked_links_by_id,
        filter_query_string=filter_query_string,
    )


PER_PAGE_OPTIONS = (50, 100, 250, 500, 1000)


def _redirect_after_hit_delete(form, deleted: int | None = None):
    """Return to the dashboard preserving pagination and filters after deleting hits."""
    return_page = 1
    return_per_page = 100
    try:
        p = form.get("return_page", type=int)
        if p is not None and p >= 1:
            return_page = p
    except (ValueError, TypeError):
        pass
    try:
        pp = form.get("return_per_page", type=int)
        if pp is not None and pp in PER_PAGE_OPTIONS:
            return_per_page = pp
    except (ValueError, TypeError):
        pass
    filters = _parse_filters_from_form(form)
    total = get_hits_count(filters=filters)
    total_pages = max(1, (total + return_per_page - 1) // return_per_page) if total else 1
    return_page = min(return_page, total_pages)
    gpu_q = None
    if "gpu_detected" in filters:
        gpu_q = "yes" if filters["gpu_detected"] else "no"
    fp_q = None
    if "fingerprint_detected" in filters:
        fp_q = "yes" if filters["fingerprint_detected"] else "no"
    repeat_q = "yes" if filters.get("repeat_visitor") else None
    visitor_q = filters.get("visitor_fp_id") or None
    qs = _filter_query_string(
        gpu=gpu_q,
        fingerprint=fp_q,
        location=filters.get("location_substring") or None,
        path=filters.get("path_substring") or None,
        hosts=filters.get("host_in") or None,
        link=filters.get("link_id") or None,
        visitor_fp=visitor_q,
        repeat=repeat_q,
        sort_visitor=bool(filters.get("sort_by_visitor_fp")),
    )
    url = "/?page={}&per_page={}{}".format(return_page, return_per_page, qs)
    if deleted:
        url += "&deleted={}".format(int(deleted))
    return redirect(url)


@app.route("/hit/<int:hit_id>/delete", methods=["POST"])
@_auth_required
def hit_delete(hit_id):
    deleted = 1 if delete_hit(hit_id) else 0
    return _redirect_after_hit_delete(request.form, deleted=deleted)


@app.route("/hits/delete", methods=["POST"])
@_auth_required
def hits_delete():
    deleted = delete_hits(request.form.getlist("hit_id"))
    return _redirect_after_hit_delete(request.form, deleted=deleted)


@app.route("/delete-all", methods=["GET", "POST"])
@_auth_required
def delete_all_route():
    if request.method == "GET":
        count = get_hits_count()
        return render_template_string(DELETE_ALL_HTML, count=count)
    confirm = (request.form.get("confirm") or "").strip()
    if confirm != "DELETE ALL":
        return redirect("/delete-all")
    n = delete_all()
    return redirect("/?deleted=" + str(n))


LINK_SORT_OPTIONS = (
    ("newest", "Newest"),
    ("oldest", "Oldest"),
    ("hits", "Most hits"),
    ("last_hit", "Last hit"),
    ("host", "Host"),
    ("label", "Label"),
)


def _render_links_page(created_url: str = "", error: str = ""):
    cfg = get_config()
    hosts = _available_link_hosts(cfg)
    selected_host = _clean_host_input(request.values.get("host") or request.cookies.get("last_link_host") or "")
    if selected_host not in hosts:
        selected_host = hosts[0] if hosts else _clean_host_input(ROOT_DOMAIN)
    settings = _effective_action_settings_for_host(cfg, selected_host)
    sort = (request.args.get("sort") or "newest").strip().lower()
    if sort not in {key for key, _ in LINK_SORT_OPTIONS}:
        sort = "newest"
    links = list_tracked_links(sort=sort)
    for link in links:
        link["full_url"] = _tracked_link_url(link.get("host"), link.get("path"))
    timezone_name = (cfg.get("timezone") or DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE
    return render_template_string(
        LINKS_HTML,
        hosts=hosts,
        selected_host=selected_host,
        settings=settings,
        links=links,
        created_url=created_url,
        error=error,
        sort=sort,
        sort_options=LINK_SORT_OPTIONS,
        status_options=STATUS_OPTIONS,
        timezone=timezone_name,
        format_ts_readable=_format_ts_readable,
        tracked_link_scheme=_tracked_link_public_scheme(),
        custom_token_max_len=LINK_TOKEN_MAX_LEN,
        max_generated_url_len=ACTION_URL_MAX_LEN,
        reserved_link_tokens=sorted(RESERVED_LINK_TOKENS),
        max_final_actions=MAX_FINAL_ACTIONS,
        final_actions_css=FINAL_ACTIONS_CSS,
        final_action_template=FINAL_ACTION_ACTION_TEMPLATE,
        final_actions_js=FINAL_ACTIONS_JS,
    )


@app.route("/links", methods=["GET", "POST"])
@_auth_required
def links():
    if request.method == "POST":
        host = _clean_host_input(request.form.get("host") or request.cookies.get("last_link_host") or ROOT_DOMAIN)
        try:
            link = create_tracked_link(
                host=host,
                settings=_action_settings_from_form(request.form),
                label=request.form.get("label"),
                token=request.form.get("custom_token"),
            )
            created_url = _tracked_link_url(link["host"], link["path"])
            response = make_response(_render_links_page(created_url=created_url))
            response.set_cookie(
                "last_link_host",
                link["host"],
                max_age=60 * 60 * 24 * 180,
                secure=request.is_secure or _external_scheme() == "https",
                httponly=True,
                samesite="Lax",
            )
            return response
        except (RuntimeError, ValueError):
            return _render_links_page(error="Unable to create link. Check that the custom URL text is unique and URL-safe."), 400
    return _render_links_page()


@app.route("/links/<int:link_id>", methods=["GET", "POST"])
@_auth_required
def link_detail(link_id):
    saved = False
    if request.method == "POST":
        updated = update_tracked_link(
            link_id,
            {
                "label": request.form.get("label"),
                "active": request.form.get("active") == "1",
                "settings": _action_settings_from_form(request.form),
            },
        )
        if not updated:
            return redirect("/links")
        saved = True
    cfg = get_config()
    link = get_tracked_link_stats(link_id)
    if not link:
        return redirect("/links")
    timezone_name = (cfg.get("timezone") or DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE
    return render_template_string(
        LINK_DETAIL_HTML,
        link=link,
        full_url=_tracked_link_url(link.get("host"), link.get("path")),
        status_options=STATUS_OPTIONS,
        timezone=timezone_name,
        format_ts_readable=_format_ts_readable,
        saved=saved,
        max_final_actions=MAX_FINAL_ACTIONS,
        final_actions_css=FINAL_ACTIONS_CSS,
        final_action_template=FINAL_ACTION_ACTION_TEMPLATE,
        final_actions_js=FINAL_ACTIONS_JS,
    )


@app.route("/settings", methods=["GET", "POST"])
@_auth_required
def settings():
    saved = False
    cfg = get_config()
    mode = "error"
    if request.method == "POST":
        parsed_action = _action_settings_from_json(request.form.get("action_settings_json"))
        if parsed_action is not None:
            updates = dict(parsed_action)
        else:
            updates = dict(_action_settings_from_form(request.form))
        mode = updates.get("mode", "error")
        tz_raw = (request.form.get("timezone") or "").strip()
        if tz_raw:
            try:
                ZoneInfo(tz_raw)
                updates["timezone"] = tz_raw
            except (ValueError, Exception):
                pass
        host_settings_json = request.form.get("host_settings_json") or ""
        if host_settings_json.strip():
            try:
                updates["host_settings"] = json.loads(host_settings_json)
            except (ValueError, TypeError):
                pass
        nr_raw = request.form.get("notification_rules_json")
        if nr_raw is not None:
            nr_raw = nr_raw.strip()
            if nr_raw:
                try:
                    parsed_nr = json.loads(nr_raw)
                    if isinstance(parsed_nr, list):
                        updates["notification_rules"] = parsed_nr
                except (ValueError, TypeError):
                    pass
            else:
                updates["notification_rules"] = []
        save_config(updates)
        saved = True
        cfg = get_config()
    else:
        if (cfg.get("default_redirect_url") or "").strip():
            mode = "redirect"
        elif (cfg.get("media_url") or "").strip() and (cfg.get("media_type") or "").strip():
            mode = "media"
        else:
            mode = "error"
    return render_template_string(
        SETTINGS_HTML,
        default_redirect_url=cfg.get("default_redirect_url", ""),
        media_url=cfg.get("media_url", ""),
        media_type=cfg.get("media_type", ""),
        media_tab_mode=cfg.get("media_tab_mode") or "none",
        media_tab_static_text=cfg.get("media_tab_static_text") or "",
        media_tab_scrolling_text=cfg.get("media_tab_scrolling_text") or "",
        media_tab_rotating_messages=cfg.get("media_tab_rotating_messages") or "",
        media_tab_rotate_interval_sec=int(cfg.get("media_tab_rotate_interval_sec", 3)),
        status_code=int(cfg.get("status_code", 404)),
        saved=saved,
        mode=mode,
        host_settings=cfg.get("host_settings") or {},
        notification_rules=cfg.get("notification_rules") or [],
        timezone=(cfg.get("timezone") or DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE,
        status_options=STATUS_OPTIONS,
        action_settings_initial=normalize_action_settings(cfg),
        max_final_actions=MAX_FINAL_ACTIONS,
        final_actions_css=FINAL_ACTIONS_CSS,
        final_action_template=FINAL_ACTION_ACTION_TEMPLATE,
        final_actions_js=FINAL_ACTIONS_JS,
    )


def _nginx_config_block() -> str:
    upstream = os.environ.get("TRAP_UPSTREAM", "honey:4040")
    return f"""# NPM+ Advanced tab (paste only the lines below, not the location wrapper):
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Connection "";
proxy_buffering off;

# Full nginx location block (manual nginx / reference only):
# location / {{
#     proxy_pass http://{upstream};
#     proxy_http_version 1.1;
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#     proxy_set_header Connection "";
#     proxy_buffering off;
# }}
"""


@app.route("/nginx")
@_auth_required
def nginx():
    return render_template_string(
        NGINX_HTML,
        nginx_config=_nginx_config_block(),
    )


@app.route("/api/geo-stats")
@_auth_required
def api_geo_stats():
    """Return aggregated hit coordinates for mapping: list [{lat, lng, weight}, ...] or GeoJSON."""
    limit = request.args.get("limit", "5000", type=int)
    limit = min(max(1, limit), 20000)
    round_digits = request.args.get("round", 3, type=int)
    round_digits = min(max(1, round_digits), 6)
    fmt = (request.args.get("format") or "list").strip().lower()
    points = get_geo_stats(limit=limit, round_digits=round_digits)
    if fmt == "geojson":
        features = [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [p["lng"], p["lat"]]},
                "properties": {"weight": p["weight"]},
            }
            for p in points
        ]
        return jsonify({"type": "FeatureCollection", "features": features})
    return jsonify(points)


@app.route("/api/media-files")
@_auth_required
def api_media_files():
    """List media files in MEDIA_DIR for the Settings media dropdown."""
    files = _list_media_files()
    return jsonify(files)


@app.route("/api/distinct-hosts")
@_auth_required
def api_distinct_hosts():
    """Distinct hosts seen in hits (for adding per-host settings)."""
    return jsonify(get_distinct_hosts())


@app.route("/api/notification-rule-test", methods=["POST"])
@_auth_required
def api_notification_rule_test():
    """Send one Discord preview message using the rule's webhook (admin-only)."""
    if not _notification_rule_test_rate_ok(request.remote_addr or ""):
        return jsonify(ok=False, message="Wait a few seconds between test sends."), 429
    data = request.get_json(silent=True) or {}
    snapshot = data.get("rule_snapshot")
    if not isinstance(snapshot, dict):
        return jsonify(ok=False, message="Missing rule data."), 400
    norm = normalize_notification_rules([snapshot])
    if not norm:
        return jsonify(ok=False, message="Invalid rule."), 400
    rule = norm[0]
    ok, code = send_discord_notification_test(rule)
    if ok:
        return jsonify(ok=True, message="Test notification sent.")
    if code == "unsupported_channel":
        return jsonify(ok=False, message="Tests support Discord webhooks only."), 400
    if code == "no_webhook":
        return jsonify(ok=False, message="Enter a valid Discord webhook URL first."), 400
    if code == "network_error":
        return jsonify(ok=False, message="Could not reach Discord."), 502
    if isinstance(code, str) and code.startswith("discord_http_"):
        return jsonify(ok=False, message="Discord rejected the request (check the webhook URL)."), 502
    return jsonify(ok=False, message="Could not send test."), 502
