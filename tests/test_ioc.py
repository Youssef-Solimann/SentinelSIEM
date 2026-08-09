"""Tests for reports/ioc.py."""
import json
from datetime import timedelta

from reports.ioc import build_iocs, export_iocs_json
from models.severity import Severity
from tests.helpers import DEFAULT_TIME, make_finding


def test_build_iocs_excludes_none_source_ip():
    findings = [make_finding(source_ip=None)]
    assert build_iocs(findings) == []


def test_build_iocs_aggregates_by_ip():
    findings = [
        make_finding(source_ip="203.0.113.5", title="SSH Brute Force Detected", severity=Severity.HIGH),
        make_finding(source_ip="203.0.113.5", title="Successful Login After Repeated Failures", severity=Severity.CRITICAL),
    ]
    iocs = build_iocs(findings)

    assert len(iocs) == 1
    ioc = iocs[0]
    assert ioc["indicator"] == "203.0.113.5"
    assert ioc["type"] == "ip"
    assert ioc["finding_count"] == 2
    assert ioc["finding_titles"] == sorted(["SSH Brute Force Detected", "Successful Login After Repeated Failures"])
    assert ioc["severities"] == sorted(["high", "critical"])
    assert "T1110 - Brute Force" in ioc["attack_techniques"]


def test_build_iocs_tracks_first_and_last_seen():
    early = DEFAULT_TIME
    late = DEFAULT_TIME + timedelta(hours=2)
    findings = [
        make_finding(source_ip="203.0.113.5", timestamp=late),
        make_finding(source_ip="203.0.113.5", timestamp=early),
    ]
    ioc = build_iocs(findings)[0]

    assert ioc["first_seen"] == early.isoformat()
    assert ioc["last_seen"] == late.isoformat()


def test_build_iocs_sorted_by_finding_count_descending():
    findings = (
        [make_finding(source_ip="1.1.1.1")] * 1
        + [make_finding(source_ip="2.2.2.2")] * 3
    )
    iocs = build_iocs(findings)

    assert [ioc["indicator"] for ioc in iocs] == ["2.2.2.2", "1.1.1.1"]


def test_export_iocs_json_writes_valid_json_matching_build_iocs(tmp_path):
    findings = [make_finding(source_ip="203.0.113.5")]
    output_path = tmp_path / "iocs.json"

    returned = export_iocs_json(findings, str(output_path))

    assert output_path.exists()
    with open(output_path) as f:
        written = json.load(f)

    assert written == returned
    assert written == build_iocs(findings)
