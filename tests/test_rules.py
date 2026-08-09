"""Tests for rules/loader.py and its wiring into the detectors."""
from datetime import timedelta

import rules.loader as loader_module
from rules.loader import get_section, load_rules


def test_load_rules_returns_all_expected_sections():
    rules = load_rules()
    expected_sections = {
        "bruteforce", "successful_login", "portscan",
        "unusual_login", "privilege", "impossible_travel",
    }
    assert expected_sections.issubset(rules.keys())


def test_get_section_returns_expected_bruteforce_values():
    assert get_section("bruteforce") == {"failure_threshold": 5, "time_window_minutes": 5}


def test_get_section_returns_empty_dict_for_unknown_section():
    assert get_section("does_not_exist") == {}


def test_missing_config_file_falls_back_to_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(loader_module, "CONFIG_PATH", str(tmp_path / "does_not_exist.yaml"))

    assert load_rules() == {}
    assert get_section("bruteforce") == {}


def test_invalid_yaml_falls_back_to_empty(monkeypatch, tmp_path):
    bad_config = tmp_path / "config.yaml"
    bad_config.write_text("bruteforce: [unterminated")
    monkeypatch.setattr(loader_module, "CONFIG_PATH", str(bad_config))

    assert load_rules() == {}


def test_detector_constants_match_the_shipped_config_file():
    # Guards against a key-name mismatch between config.yaml and a detector's
    # get(..., default) call silently masking a broken config read with its fallback.
    from detectors.bruteforce import FAILURE_THRESHOLD, TIME_WINDOW as BRUTEFORCE_WINDOW
    from detectors.successful_login import FAILURE_THRESHOLD as SL_THRESHOLD, TIME_WINDOW as SL_WINDOW
    from detectors.portscan import DISTINCT_PATH_THRESHOLD, TIME_WINDOW as SCAN_WINDOW
    from detectors.unusual_login import BUSINESS_HOURS_START, BUSINESS_HOURS_END
    from detectors.privilege import DANGEROUS_COMMAND_KEYWORDS
    from detectors.impossible_travel import MAX_PLAUSIBLE_SPEED_KMH, MIN_DISTANCE_KM

    bruteforce_cfg = get_section("bruteforce")
    assert FAILURE_THRESHOLD == bruteforce_cfg["failure_threshold"]
    assert BRUTEFORCE_WINDOW == timedelta(minutes=bruteforce_cfg["time_window_minutes"])

    sl_cfg = get_section("successful_login")
    assert SL_THRESHOLD == sl_cfg["failure_threshold"]
    assert SL_WINDOW == timedelta(minutes=sl_cfg["time_window_minutes"])

    scan_cfg = get_section("portscan")
    assert DISTINCT_PATH_THRESHOLD == scan_cfg["distinct_path_threshold"]
    assert SCAN_WINDOW == timedelta(minutes=scan_cfg["time_window_minutes"])

    login_cfg = get_section("unusual_login")
    assert BUSINESS_HOURS_START == login_cfg["business_hours_start"]
    assert BUSINESS_HOURS_END == login_cfg["business_hours_end"]

    privilege_cfg = get_section("privilege")
    assert DANGEROUS_COMMAND_KEYWORDS == privilege_cfg["dangerous_keywords"]

    travel_cfg = get_section("impossible_travel")
    assert MAX_PLAUSIBLE_SPEED_KMH == travel_cfg["max_plausible_speed_kmh"]
    assert MIN_DISTANCE_KM == travel_cfg["min_distance_km"]
