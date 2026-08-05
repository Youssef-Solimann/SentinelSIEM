from datetime import timedelta
from .base import BaseDetector
from models.finding import Finding

DISTINCT_PATH_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=2)


class PortScanDetector(BaseDetector):
    def detect(self, events):
        findings = []

        web_events = [e for e in events if e.event_type == "http_request"]

        by_ip = {}
        for event in web_events:
            by_ip.setdefault(event.source_ip, []).append(event)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)

            for i in range(len(ip_events)):
                window_start = ip_events[i].timestamp
                window_end = window_start + TIME_WINDOW
                window_events = [e for e in ip_events[i:] if e.timestamp <= window_end]

                distinct_paths = {e.extra["path"] for e in window_events}

                if len(distinct_paths) >= DISTINCT_PATH_THRESHOLD:
                    findings.append(Finding(
                        title="Possible Port/Path Scan Detected",
                        severity="medium",
                        event_type="http_request",
                        source_ip=ip,
                        timestamp=window_start,
                        description=(
                            f"{len(distinct_paths)} distinct paths requested from {ip} "
                            f"within {TIME_WINDOW}"
                        ),
                        evidence=window_events,
                    ))
                    break

        return findings