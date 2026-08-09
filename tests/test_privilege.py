"""Tests for PrivilegeEscalationDetector."""
from detectors.privilege import PrivilegeEscalationDetector
from models.severity import Severity
from tests.helpers import make_event


def sudo_event(command, target_user="root"):
    return make_event(
        event_type="sudo_command", source_ip=None, status="executed",
        extra={"command": command, "target_user": target_user},
    )


def test_empty_input_produces_no_findings():
    assert PrivilegeEscalationDetector().detect([]) == []


def test_dangerous_keyword_triggers_finding():
    findings = PrivilegeEscalationDetector().detect([sudo_event("useradd attacker")])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].source_ip is None


def test_matching_is_case_insensitive():
    findings = PrivilegeEscalationDetector().detect([sudo_event("USERADD attacker")])
    assert len(findings) == 1


def test_benign_command_triggers_nothing():
    assert PrivilegeEscalationDetector().detect([sudo_event("systemctl restart nginx")]) == []


def test_command_matching_multiple_keywords_produces_one_finding():
    findings = PrivilegeEscalationDetector().detect([sudo_event("cat /etc/shadow && useradd x")])
    assert len(findings) == 1


def test_non_sudo_events_are_ignored():
    assert PrivilegeEscalationDetector().detect([make_event(event_type="ssh_failed_login")]) == []
