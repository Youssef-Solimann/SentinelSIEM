"""Tests for NginxLogParser."""
from datetime import datetime, timezone

from parsers.nginx_parser import NginxLogParser


def test_parses_valid_line():
    line = '198.51.100.23 - - [24/Jul/2026:05:12:01 +0000] "GET /admin HTTP/1.1" 404 178 "-" "python-requests/2.31.0"'
    event = NginxLogParser().parse_line(line)

    assert event is not None
    assert event.source == "nginx"
    assert event.source_ip == "198.51.100.23"
    assert event.event_type == "http_request"
    assert event.status == "404"
    assert event.extra["path"] == "/admin"
    assert event.extra["agent"] == "python-requests/2.31.0"
    assert event.timestamp == datetime(2026, 7, 24, 5, 12, 1, tzinfo=timezone.utc)


def test_malformed_line_returns_none():
    assert NginxLogParser().parse_line("garbage input, not a log line") is None


def test_parse_file_skips_unparseable_lines(tmp_path):
    log_file = tmp_path / "nginx.log"
    log_file.write_text(
        '198.51.100.23 - - [24/Jul/2026:05:12:01 +0000] "GET /admin HTTP/1.1" 404 178 "-" "curl/8.0"\n'
        "not a valid line\n"
        '192.168.1.50 - - [24/Jul/2026:05:12:05 +0000] "GET /login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
    )

    events = NginxLogParser().parse_file(str(log_file))

    assert len(events) == 2
    assert [e.source_ip for e in events] == ["198.51.100.23", "192.168.1.50"]
