"""Tests for reports/stats.py."""
from reports.stats import build_summary, count_by_severity, most_common_finding_type, top_attacking_ip
from models.severity import Severity
from tests.helpers import make_finding


def test_count_by_severity_only_includes_present_severities():
    findings = [make_finding(severity=Severity.HIGH), make_finding(severity=Severity.HIGH)]
    counts = count_by_severity(findings)

    assert counts == {Severity.HIGH: 2}
    assert Severity.LOW not in counts


def test_count_by_severity_empty_input():
    assert count_by_severity([]) == {}


def test_top_attacking_ip_excludes_none():
    findings = [
        make_finding(source_ip="203.0.113.5"),
        make_finding(source_ip=None),
        make_finding(source_ip="203.0.113.5"),
    ]
    result = top_attacking_ip(findings)

    assert result == [("203.0.113.5", 2)]


def test_top_attacking_ip_sorted_descending_and_respects_limit():
    findings = (
        [make_finding(source_ip="1.1.1.1")] * 3
        + [make_finding(source_ip="2.2.2.2")] * 5
        + [make_finding(source_ip="3.3.3.3")] * 1
    )
    result = top_attacking_ip(findings, limit=2)

    assert result == [("2.2.2.2", 5), ("1.1.1.1", 3)]


def test_most_common_finding_type_sorted_descending():
    findings = (
        [make_finding(title="A")] * 1
        + [make_finding(title="B")] * 3
    )
    result = most_common_finding_type(findings)

    assert result == [("B", 3), ("A", 1)]


def test_build_summary_combines_everything():
    events = [object(), object(), object()]
    findings = [make_finding(source_ip="203.0.113.5", title="X", severity=Severity.CRITICAL)]

    summary = build_summary(events, findings)

    assert summary["total_events"] == 3
    assert summary["total_findings"] == 1
    assert summary["by_severity"] == {Severity.CRITICAL: 1}
    assert summary["top_ips"] == [("203.0.113.5", 1)]
    assert summary["top_finding_types"] == [("X", 1)]
