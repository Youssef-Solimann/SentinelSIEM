"""Tests for reports/attack.py."""
from reports.attack import get_technique
from tests.helpers import make_finding


def test_known_title_returns_mapped_technique():
    finding = make_finding(title="SSH Brute Force Detected")
    technique = get_technique(finding)

    assert technique["technique_id"] == "T1110"
    assert technique["technique_name"] == "Brute Force"


def test_unknown_title_returns_none():
    finding = make_finding(title="Some Future Detector That Doesn't Exist Yet")
    assert get_technique(finding) is None


def test_impossible_travel_maps_to_valid_accounts():
    finding = make_finding(title="Impossible Travel Detected")
    technique = get_technique(finding)

    assert technique["technique_id"] == "T1078"
    assert technique["technique_name"] == "Valid Accounts"
