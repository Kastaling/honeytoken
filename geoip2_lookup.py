"""GeoIP2 lookup for latitude, longitude, and location from visitor IP (IPv4/IPv6)."""
import os
from typing import Any

_GEOIP_READER = None


def _get_reader():
    global _GEOIP_READER
    if _GEOIP_READER is not None:
        return _GEOIP_READER
    path = os.environ.get("GEOIP2_DB", "").strip()
    if not path or not os.path.isfile(path):
        return None
    try:
        import geoip2.database
        _GEOIP_READER = geoip2.database.Reader(path)
        return _GEOIP_READER
    except Exception:
        return None


def _normalize_ip(ip: str) -> str | None:
    """Return IP string for lookup; skip loopback only."""
    if not ip or not ip.strip():
        return None
    ip = ip.strip()
    if ip == "::1" or ip == "127.0.0.1":
        return None
    if ip.startswith("127."):
        return None
    return ip


def get_lat_lng_city(ip: str) -> dict[str, Any] | None:
    """Return {latitude, longitude, city, region, country, location_display} from GeoIP2.
    Compatible with IPv4 and IPv6. Falls back to subdivision (region) or country when city is None.
    """
    ip = _normalize_ip(ip)
    if ip is None:
        return None
    reader = _get_reader()
    if not reader:
        return None
    try:
        r = reader.city(ip)
    except Exception:
        return None
    loc = getattr(r, "location", None)
    if loc is None:
        return None
    lat = getattr(loc, "latitude", None)
    lon = getattr(loc, "longitude", None)
    if lat is None or lon is None:
        return None

    city = None
    if getattr(r, "city", None) and getattr(r.city, "name", None):
        city = (r.city.name or "").strip() or None

    region = None
    try:
        subs = getattr(r, "subdivisions", None)
        if subs and hasattr(subs, "most_specific"):
            ms = subs.most_specific
            if getattr(ms, "name", None):
                region = (ms.name or "").strip() or None
    except Exception:
        pass

    country = None
    if getattr(r, "country", None) and getattr(r.country, "name", None):
        country = (r.country.name or "").strip() or None

    # Fallback for display: city, then region, then country
    name_primary = city or region or country

    # Formatted string: 'City, Region, Country' or 'Region, Country' when city missing
    parts = []
    if city:
        parts.append(city)
    if region and region != city:
        parts.append(region)
    if country and country != region and country != city:
        parts.append(country)
    location_display = ", ".join(parts) if parts else (country or name_primary or None)

    return {
        "latitude": lat,
        "longitude": lon,
        "city": name_primary,
        "region": region,
        "country": country,
        "location_display": location_display,
    }
