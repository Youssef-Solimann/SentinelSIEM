"""Detects successful SSH logins that occur outside normal business hours."""
from .base import BaseDetector
from models.finding import Finding
from models.severity import Severity

BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18


class UnusualLoginTimeDetector(BaseDetector):
    def detect(self, events):
        findings = []

        accepted_logins = [e for e in events if e.event_type == "ssh_accepted_login"]

        for event in accepted_logins:
            hour = event.timestamp.hour
            if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
                findings.append(Finding(
                    title="Login Outside Business Hours",
                    severity=Severity.LOW,
                    event_type="ssh_accepted_login",
                    source_ip=event.source_ip,
                    timestamp=event.timestamp,
                    description=(
                        f"Successful login by '{event.user}' from {event.source_ip} "
                        f"at {event.timestamp.strftime('%H:%M')}, outside business hours "
                        f"({BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00)"
                    ),
                    evidence=[event],
                ))

        return findings