"""Persistent store for hits and generated tracking links."""
import json
import re
import secrets
import threading
from datetime import datetime

from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from visitor_fingerprint import visitor_fp_filter_token, visitor_fp_short
from db import init_db, get_session
from models import Hit, TrackedLink

# Filter limits for security
FILTER_LOCATION_MAX_LEN = 200
FILTER_PATH_MAX_LEN = 200
FILTER_HOST_MAX_ITEMS = 50
FILTER_HOST_MAX_LEN = 255
FILTER_LINK_MAX_ITEMS = 50
FILTER_VISITOR_FP_MAX_LEN = 64
LINK_LABEL_MAX_LEN = 200
LINK_TOKEN_MAX_LEN = 96
LINK_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$")
RESERVED_LINK_TOKENS = {"api", "capture", "error", "favicon.ico", "l", "media"}


def _escape_like(s: str) -> str:
    """Escape percent, underscore, and backslash for safe use in LIKE patterns."""
    if not s:
        return ""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _apply_filters(query, filters: dict):
    """Apply filter criteria to a Hit query. Modifies in place; returns query."""
    if not filters:
        return query
    # GPU detected: client_fingerprint has non-empty webgl_renderer
    gpu = filters.get("gpu_detected")
    if gpu is True:
        query = query.filter(
            Hit.client_fingerprint.isnot(None),
            text("trim(coalesce(json_extract(client_fingerprint, '$.webgl_renderer'), '')) != ''"),
        )
    elif gpu is False:
        query = query.filter(
            or_(
                Hit.client_fingerprint.is_(None),
                text("trim(coalesce(json_extract(client_fingerprint, '$.webgl_renderer'), '')) = ''"),
            )
        )
    # Fingerprint detected: visitor id or legacy canvas hash
    fp = filters.get("fingerprint_detected")
    if fp is True:
        query = query.filter(
            or_(
                Hit.visitor_fp_id.isnot(None),
                text("trim(coalesce(json_extract(client_fingerprint, '$.canvas_hash'), '')) != ''"),
            )
        )
    elif fp is False:
        query = query.filter(
            Hit.visitor_fp_id.is_(None),
            or_(
                Hit.client_fingerprint.is_(None),
                text("trim(coalesce(json_extract(client_fingerprint, '$.canvas_hash'), '')) = ''"),
            ),
        )
    loc = filters.get("location_substring")
    if loc and len(loc) <= FILTER_LOCATION_MAX_LEN:
        pattern = ("%" + _escape_like(loc) + "%").lower()
        query = query.filter(func.lower(Hit.location_display).like(pattern, escape="\\"))
    path_sub = filters.get("path_substring")
    if path_sub and len(path_sub) <= FILTER_PATH_MAX_LEN:
        pattern = ("%" + _escape_like(path_sub) + "%").lower()
        query = query.filter(func.lower(Hit.path).like(pattern, escape="\\"))
    host_list = filters.get("host_in")
    if host_list and len(host_list) <= FILTER_HOST_MAX_ITEMS:
        normalized = [str(h).strip().lower()[:FILTER_HOST_MAX_LEN] for h in host_list if str(h).strip()]
        if normalized:
            query = query.filter(func.lower(Hit.host).in_(normalized))
    link_id = filters.get("link_id")
    if link_id not in (None, ""):
        try:
            query = query.filter(Hit.link_id == int(link_id))
        except (TypeError, ValueError):
            pass
    link_ids = filters.get("link_id_in")
    if link_ids and len(link_ids) <= FILTER_LINK_MAX_ITEMS:
        normalized_ids = []
        for item in link_ids:
            try:
                normalized_ids.append(int(item))
            except (TypeError, ValueError):
                continue
        if normalized_ids:
            query = query.filter(Hit.link_id.in_(normalized_ids))
    visitor_fp = filters.get("visitor_fp_id")
    if visitor_fp and len(visitor_fp) <= FILTER_VISITOR_FP_MAX_LEN:
        token = visitor_fp_filter_token(visitor_fp)
        if token:
            query = query.filter(Hit.visitor_fp_id.isnot(None), Hit.visitor_fp_id.like(f"{token}%"))
    if filters.get("repeat_visitor") is True:
        query = query.filter(Hit.visitor_fp_id.isnot(None))
        # prior visit exists: another hit with same fingerprint and lower id
        query = query.filter(
            text(
                "EXISTS (SELECT 1 FROM hits h2 WHERE h2.visitor_fp_id = hits.visitor_fp_id "
                "AND h2.id < hits.id)"
            )
        )
    return query

_LOCK = threading.Lock()


def _session() -> Session:
    return get_session()


def _ensure_db():
    init_db()


def add_hit(record: dict) -> int:
    """Insert a hit; return the new hit id."""
    _ensure_db()
    with _LOCK:
        s = _session()
        try:
            hit = Hit(
                ip=record.get("ip", ""),
                host=record.get("host"),
                path=record.get("path", ""),
                method=record.get("method", "GET"),
                headers=json.dumps(record.get("headers") or {}),
                fingerprint=json.dumps(record.get("fingerprint") or {}),
                query_string=record.get("query_string"),
                location=json.dumps(record.get("location") or {}),
                location_display=record.get("location_display"),
                latitude=record.get("latitude"),
                longitude=record.get("longitude"),
                city=record.get("city"),
                client_fingerprint=json.dumps(record.get("client_fingerprint") or {}) if record.get("client_fingerprint") else None,
                link_id=record.get("link_id"),
                capture_token=record.get("capture_token"),
            )
            s.add(hit)
            s.commit()
            s.refresh(hit)
            return hit.id
        finally:
            s.close()


def get_hits(limit: int = 500, offset: int = 0, filters: dict | None = None) -> list:
    s = _session()
    try:
        _ensure_db()
        q = s.query(Hit)
        q = _apply_filters(q, filters or {})
        if filters and filters.get("sort_by_visitor_fp"):
            q = q.order_by(Hit.visitor_fp_id.asc(), Hit.created_at.desc())
        else:
            q = q.order_by(Hit.created_at.desc())
        rows = q.offset(offset).limit(limit).all()
        return [h.to_dict() for h in rows]
    finally:
        s.close()


def get_hits_count(filters: dict | None = None) -> int:
    """Total number of hits (for pagination); optional filters."""
    s = _session()
    try:
        _ensure_db()
        q = s.query(Hit)
        q = _apply_filters(q, filters or {})
        return q.count()
    finally:
        s.close()


def get_distinct_hosts(limit: int = 100) -> list[str]:
    """Return distinct non-empty host values from hits (for auto-detect in settings)."""
    s = _session()
    try:
        _ensure_db()
        rows = (
            s.query(Hit.host)
            .filter(Hit.host.isnot(None), Hit.host != "")
            .distinct()
            .limit(limit)
            .all()
        )
        return [r[0].strip() for r in rows if r[0] and r[0].strip()]
    finally:
        s.close()


def _link_to_dict(link: TrackedLink, stats: dict | None = None) -> dict:
    data = link.to_dict()
    if stats:
        data.update(stats)
    return data


def _normalize_link_token(token: str) -> str:
    token = (token or "").strip()[:LINK_TOKEN_MAX_LEN]
    if not LINK_TOKEN_RE.fullmatch(token):
        return ""
    return token


def _normalize_custom_link_token(token: str) -> str:
    """Normalize an admin-entered path segment for custom root-path links."""
    raw = (token or "").strip()
    if raw.startswith("/l/"):
        raw = raw[3:]
    raw = raw.strip().strip("/")
    raw = re.sub(r"\s+", "-", raw)[:LINK_TOKEN_MAX_LEN]
    return _normalize_link_token(raw)


def _normalize_link_host(host: str) -> str:
    return (host or "").strip().lower()[:FILTER_HOST_MAX_LEN]


def _normalize_link_label(label: str | None) -> str:
    return (label or "").strip()[:LINK_LABEL_MAX_LEN]


def _generate_link_token() -> str:
    return secrets.token_urlsafe(9).rstrip("=")


def _tracked_link_path(token: str) -> str:
    return f"/l/{token}"


def _custom_link_path(token: str) -> str:
    return f"/{token}"


def create_tracked_link(host: str, settings: dict, label: str | None = None, token: str | None = None) -> dict:
    """Create a generated link with independently stored final-action settings."""
    _ensure_db()
    normalized_host = _normalize_link_host(host)
    if not normalized_host:
        raise ValueError("host is required")
    clean_settings = normalize_action_settings(settings)
    clean_label = _normalize_link_label(label)
    with _LOCK:
        s = _session()
        try:
            custom_token_provided = bool((token or "").strip())
            token = _normalize_custom_link_token(token or "")
            if custom_token_provided and not token:
                raise ValueError("invalid link path")
            if custom_token_provided and token.lower() in RESERVED_LINK_TOKENS:
                raise ValueError("reserved link path")
            if token:
                if s.query(TrackedLink.id).filter(TrackedLink.token == token).first():
                    raise ValueError("link path already exists")
            else:
                for _ in range(10):
                    candidate = _generate_link_token()
                    if not s.query(TrackedLink.id).filter(TrackedLink.token == candidate).first():
                        token = candidate
                        break
            if not token:
                raise RuntimeError("could not generate unique link token")
            link = TrackedLink(
                token=token,
                host=normalized_host,
                path=_custom_link_path(token) if custom_token_provided else _tracked_link_path(token),
                label=clean_label,
                settings=json.dumps(clean_settings),
                active=True,
            )
            s.add(link)
            s.commit()
            s.refresh(link)
            return link.to_dict()
        finally:
            s.close()


def get_tracked_link(link_id: int) -> dict | None:
    s = _session()
    try:
        _ensure_db()
        link = s.query(TrackedLink).filter(TrackedLink.id == int(link_id)).first()
        return link.to_dict() if link else None
    finally:
        s.close()


def get_tracked_link_by_token(token: str) -> dict | None:
    token = _normalize_link_token(token)
    if not token:
        return None
    s = _session()
    try:
        _ensure_db()
        link = s.query(TrackedLink).filter(TrackedLink.token == token, TrackedLink.active.is_(True)).first()
        return link.to_dict() if link else None
    finally:
        s.close()


def get_tracked_link_by_path(host: str, path: str) -> dict | None:
    """Resolve a generated custom-path link by host and request path."""
    normalized_host = _normalize_link_host(host)
    normalized_path = "/" + (path or "").strip().lstrip("/")
    if not normalized_host or normalized_path in ("", "/"):
        return None
    s = _session()
    try:
        _ensure_db()
        link = (
            s.query(TrackedLink)
            .filter(
                func.lower(TrackedLink.host) == normalized_host,
                TrackedLink.path == normalized_path[:255],
                TrackedLink.active.is_(True),
            )
            .first()
        )
        return link.to_dict() if link else None
    finally:
        s.close()


def get_tracked_links_by_ids(link_ids: list[int]) -> dict[int, dict]:
    ids = []
    for link_id in link_ids:
        try:
            ids.append(int(link_id))
        except (TypeError, ValueError):
            continue
    if not ids:
        return {}
    s = _session()
    try:
        _ensure_db()
        rows = s.query(TrackedLink).filter(TrackedLink.id.in_(sorted(set(ids)))).all()
        return {row.id: row.to_dict() for row in rows}
    finally:
        s.close()


def update_tracked_link(link_id: int, updates: dict) -> dict | None:
    """Update a link's label, active flag, or cloned settings."""
    with _LOCK:
        s = _session()
        try:
            link = s.query(TrackedLink).filter(TrackedLink.id == int(link_id)).first()
            if not link:
                return None
            if "label" in updates:
                link.label = _normalize_link_label(updates.get("label"))
            if "active" in updates:
                link.active = bool(updates.get("active"))
            if "settings" in updates:
                link.settings = json.dumps(normalize_action_settings(updates.get("settings") or {}))
            link.updated_at = datetime.utcnow()
            s.commit()
            s.refresh(link)
            return link.to_dict()
        finally:
            s.close()


def get_hit_capture_context(hit_id: int) -> dict | None:
    """Return only fields needed to validate /capture and choose link settings."""
    s = _session()
    try:
        _ensure_db()
        hit = s.query(Hit.id, Hit.capture_token, Hit.link_id).filter(Hit.id == int(hit_id)).first()
        if not hit:
            return None
        return {"_id": hit.id, "capture_token": hit.capture_token, "link_id": hit.link_id}
    finally:
        s.close()


def list_tracked_links(sort: str = "newest", limit: int = 500, offset: int = 0) -> list[dict]:
    """List links with aggregate stats without loading hit rows into Python."""
    _ensure_db()
    sort = (sort or "newest").strip().lower()
    limit = min(max(1, int(limit or 500)), 1000)
    offset = max(0, int(offset or 0))
    s = _session()
    try:
        total_hits = func.count(Hit.id).label("total_hits")
        unique_ips = func.count(func.distinct(Hit.ip)).label("unique_ips")
        first_hit = func.min(Hit.created_at).label("first_hit")
        last_hit = func.max(Hit.created_at).label("last_hit")
        q = (
            s.query(TrackedLink, total_hits, unique_ips, first_hit, last_hit)
            .outerjoin(Hit, Hit.link_id == TrackedLink.id)
            .group_by(TrackedLink.id)
        )
        sort_map = {
            "newest": TrackedLink.created_at.desc(),
            "oldest": TrackedLink.created_at.asc(),
            "hits": total_hits.desc(),
            "last_hit": last_hit.desc(),
            "host": TrackedLink.host.asc(),
            "label": TrackedLink.label.asc(),
        }
        q = q.order_by(sort_map.get(sort, TrackedLink.created_at.desc()))
        rows = q.offset(offset).limit(limit).all()
        out = []
        for link, hits, ips, first, last in rows:
            out.append(_link_to_dict(link, {
                "total_hits": int(hits or 0),
                "unique_ips": int(ips or 0),
                "first_hit": first.isoformat() + "Z" if first else None,
                "last_hit": last.isoformat() + "Z" if last else None,
            }))
        return out
    finally:
        s.close()


def get_tracked_link_stats(link_id: int) -> dict | None:
    s = _session()
    try:
        _ensure_db()
        link = s.query(TrackedLink).filter(TrackedLink.id == int(link_id)).first()
        if not link:
            return None
        total_hits, unique_ips, first_hit, last_hit = (
            s.query(
                func.count(Hit.id),
                func.count(func.distinct(Hit.ip)),
                func.min(Hit.created_at),
                func.max(Hit.created_at),
            )
            .filter(Hit.link_id == link.id)
            .first()
        )
        by_host = (
            s.query(Hit.host, func.count(Hit.id).label("count"))
            .filter(Hit.link_id == link.id)
            .group_by(Hit.host)
            .order_by(func.count(Hit.id).desc())
            .limit(20)
            .all()
        )
        by_path = (
            s.query(Hit.path, func.count(Hit.id).label("count"))
            .filter(Hit.link_id == link.id)
            .group_by(Hit.path)
            .order_by(func.count(Hit.id).desc())
            .limit(20)
            .all()
        )
        data = link.to_dict()
        data.update({
            "total_hits": int(total_hits or 0),
            "unique_ips": int(unique_ips or 0),
            "first_hit": first_hit.isoformat() + "Z" if first_hit else None,
            "last_hit": last_hit.isoformat() + "Z" if last_hit else None,
            "by_host": [{"host": host or "", "count": int(count or 0)} for host, count in by_host],
            "by_path": [{"path": path or "", "count": int(count or 0)} for path, count in by_path],
        })
        return data
    finally:
        s.close()


def get_hit_by_id(hit_id: int) -> dict | None:
    s = _session()
    try:
        _ensure_db()
        hit = s.query(Hit).filter(Hit.id == hit_id).first()
        return hit.to_dict() if hit else None
    finally:
        s.close()


def update_hit(hit_id: int, update: dict) -> bool:
    with _LOCK:
        s = _session()
        try:
            hit = s.query(Hit).filter(Hit.id == hit_id).first()
            if not hit:
                return False
            if "location" in update:
                hit.location = json.dumps(update["location"]) if update["location"] else None
            if "client_fingerprint" in update:
                hit.client_fingerprint = json.dumps(update["client_fingerprint"]) if update["client_fingerprint"] else None
            if "visitor_fp_id" in update:
                fp = update.get("visitor_fp_id")
                hit.visitor_fp_id = (str(fp).strip()[:FILTER_VISITOR_FP_MAX_LEN] or None) if fp else None
            s.commit()
            return True
        finally:
            s.close()


def count_prior_visits(visitor_fp_id: str, before_hit_id: int, link_id: int | None = None) -> int:
    """Count earlier hits sharing this browser fingerprint (optional same link)."""
    fp = (visitor_fp_id or "").strip()
    if not fp or before_hit_id <= 0:
        return 0
    s = _session()
    try:
        _ensure_db()
        q = s.query(func.count()).select_from(Hit).filter(
            Hit.visitor_fp_id == fp,
            Hit.id < int(before_hit_id),
        )
        if link_id is not None:
            try:
                q = q.filter(Hit.link_id == int(link_id))
            except (TypeError, ValueError):
                pass
        return int(q.scalar() or 0)
    finally:
        s.close()


def get_visitor_visit_stats(visitor_fp_id: str | None, hit_id: int, link_id: int | None) -> dict:
    fp = (visitor_fp_id or "").strip()
    if not fp:
        return {
            "identified": False,
            "visitor_fp_id": None,
            "visitor_fp_short": "",
            "global_prior_visits": 0,
            "global_visit_number": 0,
            "link_prior_visits": 0,
            "link_visit_number": None,
            "is_repeat": False,
            "is_repeat_link": False,
        }
    global_prior = count_prior_visits(fp, hit_id, None)
    link_prior = count_prior_visits(fp, hit_id, link_id) if link_id is not None else 0
    return {
        "identified": True,
        "visitor_fp_id": fp,
        "visitor_fp_short": visitor_fp_short(fp),
        "global_prior_visits": global_prior,
        "global_visit_number": global_prior + 1,
        "link_prior_visits": link_prior,
        "link_visit_number": (link_prior + 1) if link_id is not None else None,
        "is_repeat": global_prior > 0,
        "is_repeat_link": link_prior > 0,
    }


def delete_hit(hit_id: int) -> bool:
    with _LOCK:
        s = _session()
        try:
            n = s.query(Hit).filter(Hit.id == hit_id).delete()
            s.commit()
            return n > 0
        finally:
            s.close()


def delete_hits(hit_ids: list[int]) -> int:
    """Delete a bounded set of hits by id; returns number deleted."""
    normalized = []
    for hit_id in hit_ids[:1000]:
        try:
            normalized.append(int(hit_id))
        except (TypeError, ValueError):
            continue
    normalized = sorted(set(i for i in normalized if i > 0))
    if not normalized:
        return 0
    with _LOCK:
        s = _session()
        try:
            n = s.query(Hit).filter(Hit.id.in_(normalized)).delete(synchronize_session=False)
            s.commit()
            return int(n or 0)
        finally:
            s.close()


def delete_all() -> int:
    with _LOCK:
        s = _session()
        try:
            count = s.query(Hit).count()
            s.query(Hit).delete()
            s.commit()
            return count
        finally:
            s.close()


def get_geo_stats(limit: int = 5000, round_digits: int = 3) -> list[dict]:
    """Return aggregated points for map: [{lat, lng, weight}, ...] grouped by rounded coordinates."""
    s = _session()
    try:
        _ensure_db()
        # Group by rounded lat/lng so nearby hits become one point with higher weight
        rounded_lat = func.round(Hit.latitude, round_digits)
        rounded_lng = func.round(Hit.longitude, round_digits)
        rows = (
            s.query(rounded_lat.label("lat"), rounded_lng.label("lng"), func.count().label("weight"))
            .filter(Hit.latitude.isnot(None), Hit.longitude.isnot(None))
            .group_by(rounded_lat, rounded_lng)
            .limit(limit)
            .all()
        )
        return [{"lat": float(r.lat), "lng": float(r.lng), "weight": r.weight} for r in rows]
    finally:
        s.close()
