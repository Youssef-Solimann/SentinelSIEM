"""Tests for PortScanDetector."""
from datetime import timedelta

from detectors.portscan import PortScanDetector, DISTINCT_PATH_THRESHOLD, TIME_WINDOW
from models.severity import Severity
from tests.helpers import DEFAULT_TIME, make_event

PATHS = ["/admin", "/.env", "/phpmyadmin", "/wp-login.php", "/.git/config", "/backup.zip"]


def requests(paths, ip="203.0.113.5", start=DEFAULT_TIME, spacing=timedelta(seconds=10)):
    return [
        make_event(
            event_type="http_request", source_ip=ip,
            timestamp=start + spacing * i, extra={"path": path},
        )
        for i, path in enumerate(paths)
    ]


def test_empty_input_produces_no_findings():
    assert PortScanDetector().detect([]) == []


def test_threshold_distinct_paths_triggers_finding():
    events = requests(PATHS[:DISTINCT_PATH_THRESHOLD])
    findings = PortScanDetector().detect(events)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert len(findings[0].evidence) == DISTINCT_PATH_THRESHOLD


def test_under_threshold_distinct_paths_triggers_nothing():
    events = requests(PATHS[:DISTINCT_PATH_THRESHOLD - 1])
    assert PortScanDetector().detect(events) == []


def test_repeated_paths_do_not_count_as_distinct():
    events = requests(["/admin"] * DISTINCT_PATH_THRESHOLD)
    assert PortScanDetector().detect(events) == []


def test_paths_spread_beyond_window_do_not_trigger():
    events = requests(PATHS[:DISTINCT_PATH_THRESHOLD], spacing=TIME_WINDOW + timedelta(minutes=1))
    assert PortScanDetector().detect(events) == []


def test_only_the_ip_crossing_threshold_is_flagged():
    events = (
        requests(PATHS[:DISTINCT_PATH_THRESHOLD], ip="203.0.113.5")
        + requests(PATHS[:DISTINCT_PATH_THRESHOLD - 1], ip="198.51.100.20")
    )
    findings = PortScanDetector().detect(events)

    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.5"


def test_non_http_events_are_ignored():
    events = requests(PATHS[:DISTINCT_PATH_THRESHOLD - 1]) + [make_event(event_type="ssh_failed_login")]
    assert PortScanDetector().detect(events) == []
