"""TCP/IP fingerprinting: guess OS and stack from headers."""
from typing import Any


def _ua_contains(ua: str, *substrings: str) -> bool:
    u = (ua or "").lower()
    return any(s.lower() in u for s in substrings)


def guess_os_from_ua(ua: str) -> str:
    """Guess OS from User-Agent."""
    if not ua:
        return "Unknown"
    u = ua.lower()
    if "windows nt 10" in u or "windows nt 11" in u:
        return "Windows 10/11"
    if "windows nt 6.3" in u:
        return "Windows 8.1"
    if "windows nt 6.2" in u:
        return "Windows 8"
    if "windows nt 6.1" in u:
        return "Windows 7"
    if "windows" in u:
        return "Windows"
    if "mac os x" in u or "macintosh" in u:
        return "macOS"
    if "iphone" in u or "ipad" in u:
        return "iOS"
    if "android" in u:
        return "Android"
    if "linux" in u:
        return "Linux"
    if "cros" in u:
        return "Chrome OS"
    if "bot" in u or "crawler" in u or "spider" in u:
        return "Bot/Crawler"
    return "Unknown"


def guess_browser_from_ua(ua: str) -> str:
    """Guess browser from User-Agent."""
    if not ua:
        return "Unknown"
    u = ua.lower()
    if "edg/" in u:
        return "Edge"
    if "opr/" in u or "opera" in u:
        return "Opera"
    if "chrome" in u and "chromium" in u:
        return "Chromium"
    if "chrome" in u:
        return "Chrome"
    if "firefox" in u or "fxios" in u:
        return "Firefox"
    if "safari" in u and "chrome" not in u:
        return "Safari"
    if "msie" in u or "trident" in u:
        return "Internet Explorer"
    return "Unknown"


def guess_language_region(accept_language: str) -> str:
    """Infer region/locale from Accept-Language (e.g. en-US, pt-BR)."""
    if not accept_language:
        return "Unknown"
    # Take first preferred locale (e.g. "en-US,en;q=0.9" -> en-US)
    first = accept_language.split(",")[0].strip().split(";")[0].strip()
    return first or "Unknown"


def connection_clues(connection: str) -> dict[str, Any]:
    """Connection header hints (keep-alive vs close, etc.)."""
    if not connection:
        return {"keep_alive": None, "raw": None}
    c = connection.lower().strip()
    return {
        "keep_alive": "keep-alive" in c,
        "raw": connection.strip(),
    }


def build_fingerprint(user_agent: str, accept_language: str, connection: str) -> dict[str, Any]:
    """Build fingerprint dict from User-Agent, Accept-Language, Connection."""
    return {
        "os_guess": guess_os_from_ua(user_agent),
        "browser_guess": guess_browser_from_ua(user_agent),
        "locale_guess": guess_language_region(accept_language),
        "connection": connection_clues(connection),
        "user_agent_raw": (user_agent or "").strip() or None,
        "accept_language_raw": (accept_language or "").strip() or None,
    }
