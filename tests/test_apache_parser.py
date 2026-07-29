from datetime import datetime, timezone

from parsers.apache_parser import ApacheLogParser


def test_parses_valid_line():
    parser = ApacheLogParser()
    line = '192.168.1.10 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'

    event = parser.parse_line(line)

    assert event is not None
    assert event.source_ip == "192.168.1.10"
    assert event.timestamp == datetime(2023, 10, 10, 13, 55, 36, tzinfo=timezone.utc)
    assert event.user is None
    assert event.status == "200"
    assert event.extra["method"] == "GET"
    assert event.extra["path"] == "/index.html"


def test_parses_line_with_authenticated_user():
    parser = ApacheLogParser()
    line = '192.168.1.15 - alice [10/Oct/2023:13:56:01 +0000] "POST /login HTTP/1.1" 401 512 "http://example.com/login" "Mozilla/5.0"'

    event = parser.parse_line(line)

    assert event is not None
    assert event.user == "alice"
    assert event.status == "401"


def test_returns_none_for_malformed_line():
    parser = ApacheLogParser()

    assert parser.parse_line("this is not a valid apache log line") is None


def test_parses_sample_log_file():
    parser = ApacheLogParser()

    with open("sample_logs/apache_sample.log") as f:
        lines = f.readlines()

    events = [parser.parse_line(line) for line in lines]
    parsed = [e for e in events if e is not None]

    assert len(parsed) == 4
    assert len(events) - len(parsed) == 1