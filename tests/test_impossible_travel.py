"""Tests for ImpossibleTravelDetector. Uses a fake in-memory geo_lookup -- no real network calls."""
from datetime import timedelta

from detectors.impossible_travel import ImpossibleTravelDetector
from tests.helpers import DEFAULT_TIME, make_event

# ~5570 km apart (New York <-> London-ish); "3.3.3.3" is ~5 km from "1.1.1.1", well under
# MIN_DISTANCE_KM, used to test that nearby-but-fast logins aren't flagged as noise.
GEO_DB = {
    "1.1.1.1": {"city": "New York", "country": "USA", "lat": 40.7128, "lon": -74.0060},
    "2.2.2.2": {"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
    "3.3.3.3": {"city": "New York", "country": "USA", "lat": 40.7500, "lon": -73.9800},
}


def fake_geo_lookup(ip):
    return GEO_DB.get(ip)


def login(user, ip, timestamp):
    return make_event(event_type="ssh_accepted_login", user=user, source_ip=ip, timestamp=timestamp, status="success")


def detector():
    return ImpossibleTravelDetector(geo_lookup=fake_geo_lookup)


def test_empty_input_produces_no_findings():
    assert detector().detect([]) == []


def test_single_login_has_no_pair_to_compare():
    events = [login("alice", "1.1.1.1", DEFAULT_TIME)]
    assert detector().detect(events) == []


def test_impossible_travel_is_flagged():
    events = [
        login("alice", "1.1.1.1", DEFAULT_TIME),
        login("alice", "2.2.2.2", DEFAULT_TIME + timedelta(hours=1)),
    ]
    findings = detector().detect(events)

    assert len(findings) == 1
    assert findings[0].title == "Impossible Travel Detected"
    assert findings[0].source_ip == "2.2.2.2"
    assert len(findings[0].evidence) == 2

    geo_context = findings[0].geo_context
    assert geo_context is not None
    assert len(geo_context) == 2
    assert geo_context[0]["label"] == "Previous login"
    assert geo_context[0]["ip"] == "1.1.1.1"
    assert geo_context[0]["city"] == "New York"
    assert geo_context[1]["label"] == "Current login"
    assert geo_context[1]["ip"] == "2.2.2.2"
    assert geo_context[1]["city"] == "London"


def test_plausible_travel_is_not_flagged():
    events = [
        login("alice", "1.1.1.1", DEFAULT_TIME),
        login("alice", "2.2.2.2", DEFAULT_TIME + timedelta(hours=10)),
    ]
    assert detector().detect(events) == []


def test_simultaneous_distant_logins_are_flagged():
    events = [
        login("alice", "1.1.1.1", DEFAULT_TIME),
        login("alice", "2.2.2.2", DEFAULT_TIME),
    ]
    assert len(detector().detect(events)) == 1


def test_nearby_fast_logins_are_not_flagged():
    events = [
        login("alice", "1.1.1.1", DEFAULT_TIME),
        login("alice", "3.3.3.3", DEFAULT_TIME + timedelta(seconds=1)),
    ]
    assert detector().detect(events) == []


def test_missing_geo_data_is_skipped_gracefully():
    events = [
        login("alice", "1.1.1.1", DEFAULT_TIME),
        login("alice", "9.9.9.9", DEFAULT_TIME + timedelta(hours=1)),
    ]
    assert detector().detect(events) == []


def test_different_users_are_never_compared():
    events = [
        login("alice", "1.1.1.1", DEFAULT_TIME),
        login("bob", "2.2.2.2", DEFAULT_TIME + timedelta(hours=1)),
    ]
    assert detector().detect(events) == []


def test_failed_logins_are_ignored():
    events = [
        make_event(event_type="ssh_failed_login", user="alice", source_ip="1.1.1.1", timestamp=DEFAULT_TIME),
        login("alice", "2.2.2.2", DEFAULT_TIME + timedelta(hours=1)),
    ]
    assert detector().detect(events) == []
