"""Tests for SuccessfulLoginAfterFailuresDetector."""
from datetime import timedelta

from detectors.successful_login import SuccessfulLoginAfterFailuresDetector, FAILURE_THRESHOLD, TIME_WINDOW
from models.severity import Severity
from tests.helpers import DEFAULT_TIME, make_event


def failures(count, ip="203.0.113.5", start=DEFAULT_TIME, spacing=timedelta(seconds=10)):
    return [
        make_event(event_type="ssh_failed_login", source_ip=ip, timestamp=start + spacing * i)
        for i in range(count)
    ]


def accepted(ip="203.0.113.5", timestamp=DEFAULT_TIME):
    return make_event(event_type="ssh_accepted_login", source_ip=ip, timestamp=timestamp, status="success")


def test_empty_input_produces_no_findings():
    assert SuccessfulLoginAfterFailuresDetector().detect([]) == []


def test_threshold_failures_then_success_triggers_finding():
    fails = failures(FAILURE_THRESHOLD)
    success = accepted(timestamp=fails[-1].timestamp + timedelta(seconds=10))
    findings = SuccessfulLoginAfterFailuresDetector().detect(fails + [success])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert len(findings[0].evidence) == FAILURE_THRESHOLD + 1
    assert findings[0].evidence[-1] is success


def test_under_threshold_failures_then_success_triggers_nothing():
    fails = failures(FAILURE_THRESHOLD - 1)
    success = accepted(timestamp=fails[-1].timestamp + timedelta(seconds=10))
    assert SuccessfulLoginAfterFailuresDetector().detect(fails + [success]) == []


def test_failures_outside_window_are_excluded():
    fails = failures(FAILURE_THRESHOLD, spacing=timedelta(seconds=1))
    success = accepted(timestamp=fails[-1].timestamp + TIME_WINDOW + timedelta(minutes=1))
    assert SuccessfulLoginAfterFailuresDetector().detect(fails + [success]) == []


def test_success_with_no_prior_failures_triggers_nothing():
    assert SuccessfulLoginAfterFailuresDetector().detect([accepted()]) == []


def test_counter_resets_after_each_success_no_duplicate_evidence():
    first_batch = failures(FAILURE_THRESHOLD, start=DEFAULT_TIME)
    first_success = accepted(timestamp=first_batch[-1].timestamp + timedelta(seconds=10))

    second_start = first_success.timestamp + timedelta(minutes=1)
    second_batch = failures(FAILURE_THRESHOLD, start=second_start)
    second_success = accepted(timestamp=second_batch[-1].timestamp + timedelta(seconds=10))

    events = first_batch + [first_success] + second_batch + [second_success]
    findings = SuccessfulLoginAfterFailuresDetector().detect(events)

    assert len(findings) == 2
    first_evidence_ids = {id(e) for e in findings[0].evidence}
    second_evidence_ids = {id(e) for e in findings[1].evidence}
    assert first_evidence_ids.isdisjoint(second_evidence_ids)


def test_non_ssh_events_are_ignored():
    events = failures(FAILURE_THRESHOLD - 1) + [make_event(event_type="http_request")]
    assert SuccessfulLoginAfterFailuresDetector().detect(events) == []
