"""Tests for DetectionEngine."""
from datetime import timedelta

from detectors.engine import DetectionEngine
from detectors.bruteforce import FAILURE_THRESHOLD as BRUTEFORCE_THRESHOLD
from tests.helpers import DEFAULT_TIME, make_event


def test_empty_input_produces_no_findings():
    assert DetectionEngine().run([]) == []


def test_aggregates_findings_across_multiple_detectors():
    brute_force_events = [
        make_event(event_type="ssh_failed_login", timestamp=DEFAULT_TIME + timedelta(seconds=10 * i))
        for i in range(BRUTEFORCE_THRESHOLD)
    ]
    privilege_event = make_event(
        event_type="sudo_command", source_ip=None,
        extra={"command": "useradd attacker", "target_user": "root"},
    )

    findings = DetectionEngine().run(brute_force_events + [privilege_event])
    titles = {f.title for f in findings}

    assert "SSH Brute Force Detected" in titles
    assert "Suspicious Privilege Escalation Command" in titles
    assert len(findings) == 2


def test_five_detectors_are_registered():
    assert len(DetectionEngine().detectors) == 5
