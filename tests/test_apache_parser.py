"""Tests for ApacheLogParser."""
from datetime import datetime, timezone, timedelta

from parsers.apache_parser import ApacheLogParser


def test_parses_valid_line():
    line = '192.168.1.15 - - [23/Jul/2026:10:22:31 +0000] "POST /login HTTP/1.1" 401 2326 "-" "Mozilla/5.0"'
    event = ApacheLogParser().parse_line(line)

    assert event is not None
    assert event.source == "apache"
    assert event.source_ip == "192.168.1.15"
    assert event.event_type == "http_request"
    assert event.status == "401"
    assert event.user is None
    assert event.extra["method"] == "POST"
    assert event.extra["path"] == "/login"
    assert event.timestamp == datetime(2026, 7, 23, 10, 22, 31, tzinfo=timezone.utc)


def test_dash_user_becomes_none():
    line = '10.0.0.1 - - [23/Jul/2026:10:22:31 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"'
    event = ApacheLogParser().parse_line(line)

    assert event.user is None


def test_named_user_is_preserved():
    line = '10.0.0.1 - alice [23/Jul/2026:10:22:31 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"'
    event = ApacheLogParser().parse_line(line)

    assert event.user == "alice"


def test_malformed_line_returns_none():
    assert ApacheLogParser().parse_line("this is not a valid apache log line") is None


def test_non_utc_offset_is_preserved():
    line = '10.0.0.1 - - [23/Jul/2026:10:22:31 -0500] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"'
    event = ApacheLogParser().parse_line(line)

    assert event.timestamp.utcoffset() == timedelta(hours=-5)


def test_parse_file_skips_unparseable_lines(tmp_path):
    log_file = tmp_path / "apache.log"
    log_file.write_text(
        '192.168.1.15 - - [23/Jul/2026:10:22:31 +0000] "POST /login HTTP/1.1" 401 2326 "-" "Mozilla/5.0"\n'
        "not a valid line\n"
        '10.0.0.1 - - [23/Jul/2026:10:23:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"\n'
    )

    events = ApacheLogParser().parse_file(str(log_file))

    assert len(events) == 2
    assert [e.source_ip for e in events] == ["192.168.1.15", "10.0.0.1"]
