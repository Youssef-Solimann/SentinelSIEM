"""Tests for AuthLogParser."""
from datetime import datetime, timezone

from parsers.auth_parser import AuthLogParser


def test_parses_failed_login_with_invalid_user():
    line = "Jul 24 09:12:33 webserver sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51512 ssh2"
    event = AuthLogParser(default_year=2026).parse_line(line)

    assert event is not None
    assert event.source == "auth"
    assert event.event_type == "ssh_failed_login"
    assert event.status == "failed"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.5"
    assert event.extra["port"] == "51512"
    assert event.timestamp == datetime(2026, 7, 24, 9, 12, 33, tzinfo=timezone.utc)


def test_parses_failed_login_without_invalid_user_prefix():
    line = "Jul 24 09:30:01 webserver sshd[1241]: Failed password for root from 203.0.113.5 port 51513 ssh2"
    event = AuthLogParser(default_year=2026).parse_line(line)

    assert event.event_type == "ssh_failed_login"
    assert event.user == "root"


def test_parses_accepted_login():
    line = "Jul 24 09:15:02 webserver sshd[1240]: Accepted password for youssef from 192.168.1.50 port 51000 ssh2"
    event = AuthLogParser(default_year=2026).parse_line(line)

    assert event.event_type == "ssh_accepted_login"
    assert event.status == "success"
    assert event.user == "youssef"
    assert event.source_ip == "192.168.1.50"


def test_parses_sudo_command_with_no_source_ip():
    line = "Jul 24 09:20:10 webserver sudo: youssef : TTY=pts/0 ; PWD=/home/youssef ; USER=root ; COMMAND=/bin/systemctl restart nginx"
    event = AuthLogParser(default_year=2026).parse_line(line)

    assert event.event_type == "sudo_command"
    assert event.source_ip is None
    assert event.user == "youssef"
    assert event.extra["target_user"] == "root"
    assert event.extra["command"] == "/bin/systemctl restart nginx"


def test_malformed_line_returns_none():
    assert AuthLogParser(default_year=2026).parse_line("not a syslog line at all") is None


def test_default_year_is_applied():
    line = "Jul 24 09:12:33 webserver sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51512 ssh2"
    event = AuthLogParser(default_year=2030).parse_line(line)

    assert event.timestamp.year == 2030


def test_timestamp_is_timezone_aware_utc():
    line = "Jul 24 09:12:33 webserver sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51512 ssh2"
    event = AuthLogParser(default_year=2026).parse_line(line)

    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset().total_seconds() == 0
