"""Trusted reverse-proxy detection for resolving the real client IP.

``Cf-Connecting-Ip`` is honored only when Honey's TCP peer (``remote_addr``) is
a Cloudflare edge node (ranges from ``CLOUDFLARE_IPS_FILE``). It is never read
based on ``X-Real-IP`` matching Cloudflare ranges — that would let WARP/CF-egress
clients forge visitor IPs via a client-supplied header.

Behind NPM, the visitor IP must arrive in ``X-Real-IP``. Configure NPM with
``set_real_ip_from`` (Cloudflare ranges) + ``real_ip_header CF-Connecting-IP`` at
server/http scope so ``$remote_addr`` is the visitor before the Advanced-tab
``proxy_set_header X-Real-IP $remote_addr`` line runs.

``X-Forwarded-For`` is never trusted. Direct connections to the trap port cannot
spoof visitor IPs via headers. Configure extra proxy CIDRs with
``TRUSTED_PROXY_CIDRS`` (comma-separated).
"""
from __future__ import annotations

import ipaddress
import json
import os
from functools import lru_cache
from pathlib import Path

_DEFAULT_TRUSTED_CIDRS = (
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)

_CF_IP_HEADERS = (
    "Cf-Connecting-Ip",
    "CF-Connecting-IP",
)

# Set by the reverse proxy (NPM/Caddy). Never use X-Forwarded-For here — clients can
# prepend fake addresses; only the proxy-controlled X-Real-IP is trusted.
_REAL_IP_HEADERS = (
    "X-Real-Ip",
    "X-Real-IP",
)


def _parse_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    cidr = cidr.strip()
    if not cidr:
        return None
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _cidrs_from_cloudflare_payload(data: object) -> list[str]:
    """Extract CIDR strings from Cloudflare IP list JSON variants."""
    cidrs: list[str] = []
    if isinstance(data, list):
        return [str(x) for x in data]
    if not isinstance(data, dict):
        return []

    def absorb_ranges(obj: dict) -> None:
        cidrs.extend(str(c) for c in (obj.get("ipv4_cidrs") or []))
        cidrs.extend(str(c) for c in (obj.get("ipv6_cidrs") or []))

    nested = data.get("result")
    if isinstance(nested, dict):
        absorb_ranges(nested)
    elif isinstance(nested, list):
        cidrs.extend(str(x) for x in nested)
    if "ipv4_cidrs" in data or "ipv6_cidrs" in data:
        absorb_ranges(data)
    return cidrs


def _networks_from_cloudflare_file(path: Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in _cidrs_from_cloudflare_payload(data):
        net = _parse_network(cidr)
        if net is not None:
            out.append(net)
    return out


@lru_cache(maxsize=1)
def _cloudflare_networks_by_version() -> tuple[
    tuple[ipaddress.IPv4Network, ...],
    tuple[ipaddress.IPv6Network, ...],
]:
    """Cloudflare edge ranges only (from ``CLOUDFLARE_IPS_FILE``)."""
    cf_file = (os.environ.get("CLOUDFLARE_IPS_FILE") or "").strip()
    if not cf_file:
        return (), ()
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for net in _networks_from_cloudflare_file(Path(cf_file)):
        if isinstance(net, ipaddress.IPv4Network):
            v4.append(net)
        elif isinstance(net, ipaddress.IPv6Network):
            v6.append(net)
    return tuple(v4), tuple(v6)


@lru_cache(maxsize=1)
def _trusted_networks_by_version() -> tuple[
    tuple[ipaddress.IPv4Network, ...],
    tuple[ipaddress.IPv6Network, ...],
]:
    cidrs = list(_DEFAULT_TRUSTED_CIDRS)
    env_val = (os.environ.get("TRUSTED_PROXY_CIDRS") or "").strip()
    if env_val:
        cidrs.extend(c.strip() for c in env_val.split(",") if c.strip())
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for cidr in cidrs:
        net = _parse_network(cidr)
        if isinstance(net, ipaddress.IPv4Network):
            v4.append(net)
        elif isinstance(net, ipaddress.IPv6Network):
            v6.append(net)
    cf_file = (os.environ.get("CLOUDFLARE_IPS_FILE") or "").strip()
    if cf_file:
        for net in _networks_from_cloudflare_file(Path(cf_file)):
            if isinstance(net, ipaddress.IPv4Network):
                v4.append(net)
            elif isinstance(net, ipaddress.IPv6Network):
                v6.append(net)
    return tuple(v4), tuple(v6)


def _ip_in_networks(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    v4_nets: tuple[ipaddress.IPv4Network, ...],
    v6_nets: tuple[ipaddress.IPv6Network, ...],
) -> bool:
    nets = v4_nets if addr.version == 4 else v6_nets
    return any(addr in net for net in nets)


def is_cloudflare_peer(ip: str) -> bool:
    """True when ``ip`` is a Cloudflare edge node (not NPM/Docker/LAN)."""
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    v4, v6 = _cloudflare_networks_by_version()
    if not v4 and not v6:
        return False
    return _ip_in_networks(addr, v4, v6)


def is_trusted_proxy(ip: str) -> bool:
    """True when ``ip`` is a known reverse proxy (not an end client)."""
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    v4_nets, v6_nets = _trusted_networks_by_version()
    return _ip_in_networks(addr, v4_nets, v6_nets)


def is_valid_client_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address((ip or "").strip())
        return True
    except ValueError:
        return False


def _first_valid_header_ip(get_header, header_names: tuple[str, ...]) -> str:
    for name in header_names:
        val = get_header(name)
        if not val:
            continue
        candidate = val.split(",")[0].strip()
        if candidate and is_valid_client_ip(candidate):
            return candidate
    return ""


def cloudflare_cidrs() -> tuple[str, ...]:
    """Cloudflare CIDR strings from ``CLOUDFLARE_IPS_FILE`` (for NPM real_ip config)."""
    cf_file = (os.environ.get("CLOUDFLARE_IPS_FILE") or "").strip()
    if not cf_file:
        return ()
    path = Path(cf_file)
    if not path.is_file():
        return ()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    return tuple(_cidrs_from_cloudflare_payload(data))


def client_ip_from_forwarded_headers(get_header, remote_addr: str = "") -> str:
    """Return client IP from proxy headers appropriate for the immediate peer.

    ``Cf-Connecting-Ip`` is used only when Honey's TCP peer is a Cloudflare edge
    (direct CF → Honey). Behind NPM, visitor IP must be in ``X-Real-IP`` — see
    NPM ``set_real_ip_from`` + ``real_ip_header`` setup in the admin nginx page.
    """
    remote = (remote_addr or "").strip()
    if is_cloudflare_peer(remote):
        cf_ip = _first_valid_header_ip(get_header, _CF_IP_HEADERS)
        if cf_ip:
            return cf_ip
    return _first_valid_header_ip(get_header, _REAL_IP_HEADERS)


def resolve_client_ip(remote_addr: str, get_header) -> str:
    """Resolve visitor IP; ignore forwarded headers from untrusted peers."""
    remote = (remote_addr or "").strip()
    if not is_trusted_proxy(remote):
        return remote
    forwarded = client_ip_from_forwarded_headers(get_header, remote)
    return forwarded or remote
