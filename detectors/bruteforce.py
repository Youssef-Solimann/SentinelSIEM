from datetime import timedelta
from .base import BaseDetector
from models.finding import Finding

FAILURE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)


class BruteForceDetector(BaseDetector):
    def detect(self, events):
        findings = []

        failed_logins = [e for e in events if e.event_type == "ssh_failed_login"]

        by_ip = {}
        for event in failed_logins:
            by_ip.setdefault(event.source_ip, []).append(event)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)

            for i in range(len(ip_events)):
                window_start = ip_events[i].timestamp
                window_end = window_start + TIME_WINDOW
                count = sum(1 for e in ip_events[i:] if e.timestamp <= window_end)

                if count >= FAILURE_THRESHOLD:
                    findings.append(Finding(
                        title="SSH Brute Force Detected",
                        severity="high",
                        event_type="ssh_failed_login",
                        source_ip=ip,
                        timestamp=window_start,
                        description=f"{count} failed SSH logins from {ip} within {TIME_WINDOW}",
                        evidence=ip_events[i:i + count],
                    ))
                    break  # one finding per IP is enough, don't re-flag overlapping windows

        return findings
