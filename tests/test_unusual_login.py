"""Tests for UnusualLoginTimeDetector."""
from detectors.unusual_login import UnusualLoginTimeDetector, BUSINESS_HOURS_START, BUSINESS_HOURS_END
from models.severity import Severity
from tests.helpers import DEFAULT_TIME, make_event


def login_at_hour(hour):
    return make_event(event_type="ssh_accepted_login", timestamp=DEFAULT_TIME.replace(hour=hour))


def test_empty_input_produces_no_findings():
    assert UnusualLoginTimeDetector().detect([]) == []


def test_login_before_business_hours_is_flagged():
    findings = UnusualLoginTimeDetector().detect([login_at_hour(7)])
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_login_at_start_of_business_hours_is_not_flagged():
    assert UnusualLoginTimeDetector().detect([login_at_hour(BUSINESS_HOURS_START)]) == []


def test_login_at_last_hour_before_close_is_not_flagged():
    assert UnusualLoginTimeDetector().detect([login_at_hour(BUSINESS_HOURS_END - 1)]) == []


def test_login_at_closing_hour_is_flagged():
    findings = UnusualLoginTimeDetector().detect([login_at_hour(BUSINESS_HOURS_END)])
    assert len(findings) == 1


def test_each_event_is_evaluated_independently():
    events = [login_at_hour(3), login_at_hour(12), login_at_hour(23)]
    findings = UnusualLoginTimeDetector().detect(events)

    assert len(findings) == 2
    flagged_hours = {f.timestamp.hour for f in findings}
    assert flagged_hours == {3, 23}


def test_non_accepted_login_events_are_ignored():
    events = [make_event(event_type="ssh_failed_login", timestamp=DEFAULT_TIME.replace(hour=3))]
    assert UnusualLoginTimeDetector().detect(events) == []
