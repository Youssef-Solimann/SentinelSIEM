"""Looks up geographic location for an IP address via the free ip-api.com service (no API key required)."""
import json
import urllib.error
import urllib.request

# ip-api.com's free tier is HTTP only (no HTTPS) and rate-limited (~45 req/min).
# Private/reserved ranges (like the RFC 5737 documentation IPs in sample_logs/) return
# status != "success" rather than real coordinates -- that's expected, not an error.
API_URL = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"
TIMEOUT_SECONDS = 3


def lookup_ip(ip):
    if not ip:
        return None

    try:
        with urllib.request.urlopen(API_URL.format(ip=ip), timeout=TIMEOUT_SECONDS) as response:
            data = json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None

    if data.get("status") != "success":
        return None

    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }
