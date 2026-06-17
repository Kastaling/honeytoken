"""Optional geo lookup for hits (runs in background). IPv4 and IPv6 supported (ip-api.com)."""
import threading
from typing import Any

import requests

from store import update_hit


def _fetch_location(ip: str) -> dict[str, Any] | None:
    if not ip or not ip.strip():
        return None
    ip = ip.strip()
    if ip.startswith("127.") or ip in ("::1", "127.0.0.1"):
        return None
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp",
            timeout=2,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
        }
    except Exception:
        return None


def enrich_hit_location(hit_id: int, ip: str) -> None:
    """Run in background: lookup geo for ip and update hit with location."""
    def run():
        loc = _fetch_location(ip)
        if loc:
            update_hit(hit_id, {"location": loc})
    t = threading.Thread(target=run, daemon=True)
    t.start()
