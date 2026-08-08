"""Detects a successful SSH login that follows a burst of failed logins from the same IP."""
from datetime import timedelta
from .base import BaseDetector
from models.finding import Finding
from models.severity import Severity

FAILURE_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


class SuccessfulLoginAfterFailuresDetector(BaseDetector):
    def detect(self, events):
        findings = []

        ssh_events = [e for e in events if e.event_type in ("ssh_failed_login", "ssh_accepted_login")]

        by_ip = {}
        for event in ssh_events:
            by_ip.setdefault(event.source_ip, []).append(event)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)

            recent_failures = []
            for event in ip_events:
                if event.event_type == "ssh_failed_login":
                    recent_failures.append(event)
                elif event.event_type == "ssh_accepted_login":
                    valid_failures = [
                        f for f in recent_failures
                        if event.timestamp - f.timestamp <= TIME_WINDOW
                    ]
                    if len(valid_failures) >= FAILURE_THRESHOLD:
                        findings.append(Finding(
                            title="Successful Login After Repeated Failures",
                            severity=Severity.CRITICAL,
                            event_type="ssh_accepted_login",
                            source_ip=ip,
                            timestamp=event.timestamp,
                            description=(
                                f"{len(valid_failures)} failed logins from {ip} "
                                f"immediately followed by a successful login as '{event.user}'"
                            ),
                            evidence=valid_failures + [event],
                        ))
                    recent_failures = []  # reset only after an accepted login; failures keep accumulating otherwise

        return findings