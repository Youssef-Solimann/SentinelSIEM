"""Factory helpers for building synthetic LogEvent/Finding objects in tests."""
from datetime import datetime, timezone

from models.finding import Finding
from models.severity import Severity
from parsers.base import LogEvent

DEFAULT_TIME = datetime(2026, 7, 24, 9, 0, 0, tzinfo=timezone.utc)


def make_event(**overrides):
    fields = {
        "timestamp": DEFAULT_TIME,
        "source": "auth",
        "source_ip": "203.0.113.5",
        "event_type": "ssh_failed_login",
        "user": "root",
        "status": "failed",
        "raw_line": "",
        "extra": {},
    }
    fields.update(overrides)
    return LogEvent(**fields)


def make_finding(**overrides):
    fields = {
        "title": "Test Finding",
        "severity": Severity.LOW,
        "event_type": "ssh_failed_login",
        "source_ip": "203.0.113.5",
        "timestamp": DEFAULT_TIME,
        "description": "test description",
        "evidence": [],
    }
    fields.update(overrides)
    return Finding(**fields)
