"""Tests for BruteForceDetector."""
from datetime import timedelta

from detectors.bruteforce import BruteForceDetector, FAILURE_THRESHOLD, TIME_WINDOW
from models.severity import Severity
from tests.helpers import DEFAULT_TIME, make_event


def failures(count, ip="203.0.113.5", start=DEFAULT_TIME, spacing=timedelta(seconds=10)):
    return [
        make_event(event_type="ssh_failed_login", source_ip=ip, timestamp=start + spacing * i)
        for i in range(count)
    ]


def test_empty_input_produces_no_findings():
    assert BruteForceDetector().detect([]) == []


def test_exactly_at_threshold_triggers_one_finding():
    events = failures(FAILURE_THRESHOLD)
    findings = BruteForceDetector().detect(events)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source_ip == "203.0.113.5"
    assert len(findings[0].evidence) == FAILURE_THRESHOLD


def test_one_under_threshold_triggers_nothing():
    events = failures(FAILURE_THRESHOLD - 1)
    assert BruteForceDetector().detect(events) == []


def test_failures_spread_beyond_window_do_not_trigger():
    events = failures(FAILURE_THRESHOLD, spacing=TIME_WINDOW + timedelta(minutes=1))
    assert BruteForceDetector().detect(events) == []


def test_failure_exactly_at_window_edge_still_counts():
    start = DEFAULT_TIME
    events = [
        make_event(event_type="ssh_failed_login", timestamp=start),
        make_event(event_type="ssh_failed_login", timestamp=start + timedelta(minutes=1)),
        make_event(event_type="ssh_failed_login", timestamp=start + timedelta(minutes=2)),
        make_event(event_type="ssh_failed_login", timestamp=start + timedelta(minutes=3)),
        make_event(event_type="ssh_failed_login", timestamp=start + TIME_WINDOW),
    ]
    findings = BruteForceDetector().detect(events)

    assert len(findings) == 1
    assert len(findings[0].evidence) == 5


def test_out_of_order_input_is_still_detected():
    events = failures(FAILURE_THRESHOLD)
    events.reverse()

    findings = BruteForceDetector().detect(events)
    assert len(findings) == 1


def test_only_the_ip_crossing_threshold_is_flagged():
    events = failures(FAILURE_THRESHOLD, ip="203.0.113.5") + failures(FAILURE_THRESHOLD - 1, ip="198.51.100.20")

    findings = BruteForceDetector().detect(events)

    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.5"


def test_non_failed_login_events_are_ignored():
    events = failures(FAILURE_THRESHOLD - 1) + [make_event(event_type="http_request")]
    assert BruteForceDetector().detect(events) == []
