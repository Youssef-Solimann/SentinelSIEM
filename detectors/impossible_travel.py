"""Detects a successful login for the same user from two locations too far apart to have traveled between in time."""
import math

from .base import BaseDetector
from models.finding import Finding
from models.severity import Severity
from reports.geoip import lookup_ip
from rules.loader import get_section

_RULES = get_section("impossible_travel")
MAX_PLAUSIBLE_SPEED_KMH = _RULES.get("max_plausible_speed_kmh", 900)
MIN_DISTANCE_KM = _RULES.get("min_distance_km", 100)
EARTH_RADIUS_KM = 6371


def _haversine_km(lat1, lon1, lat2, lon2):
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class ImpossibleTravelDetector(BaseDetector):
    def __init__(self, geo_lookup=lookup_ip):
        self.geo_lookup = geo_lookup

    def detect(self, events):
        findings = []

        accepted_logins = [e for e in events if e.event_type == "ssh_accepted_login" and e.user]

        by_user = {}
        for event in accepted_logins:
            by_user.setdefault(event.user, []).append(event)

        geo_cache = {}

        def geo_for(ip):
            if ip not in geo_cache:
                geo_cache[ip] = self.geo_lookup(ip)
            return geo_cache[ip]

        for user, user_events in by_user.items():
            user_events.sort(key=lambda e: e.timestamp)

            for previous, current in zip(user_events, user_events[1:]):
                previous_geo = geo_for(previous.source_ip)
                current_geo = geo_for(current.source_ip)
                if not previous_geo or not current_geo:
                    continue

                distance_km = _haversine_km(
                    previous_geo["lat"], previous_geo["lon"],
                    current_geo["lat"], current_geo["lon"],
                )
                if distance_km < MIN_DISTANCE_KM:
                    continue

                hours = (current.timestamp - previous.timestamp).total_seconds() / 3600
                speed_kmh = float("inf") if hours <= 0 else distance_km / hours

                if speed_kmh > MAX_PLAUSIBLE_SPEED_KMH:
                    findings.append(Finding(
                        title="Impossible Travel Detected",
                        severity=Severity.CRITICAL,
                        event_type="ssh_accepted_login",
                        source_ip=current.source_ip,
                        timestamp=current.timestamp,
                        description=(
                            f"'{user}' logged in from {previous_geo['city']}, {previous_geo['country']} "
                            f"({previous.source_ip}) then from {current_geo['city']}, {current_geo['country']} "
                            f"({current.source_ip}), {distance_km:.0f} km apart, "
                            f"{hours:.2f} hours apart (~{speed_kmh:.0f} km/h implied)"
                        ),
                        evidence=[previous, current],
                        geo_context=[
                            {
                                "label": "Previous login",
                                "ip": previous.source_ip,
                                "city": previous_geo["city"],
                                "country": previous_geo["country"],
                                "timestamp": previous.timestamp,
                            },
                            {
                                "label": "Current login",
                                "ip": current.source_ip,
                                "city": current_geo["city"],
                                "country": current_geo["country"],
                                "timestamp": current.timestamp,
                            },
                        ],
                    ))

        return findings
