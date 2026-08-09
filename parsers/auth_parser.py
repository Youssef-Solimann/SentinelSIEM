"""Parses Linux auth.log (syslog) lines for SSH and sudo activity into normalized LogEvent objects."""
import re
from datetime import datetime, timezone
from .base import LogEvent

SYSLOG_PREFIX_RE = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<process>\S+?):\s*(?P<message>.*)$'
)

SSH_FAILED_RE = re.compile(
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
SSH_ACCEPTED_RE = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
SUDO_RE = re.compile(
    r'(?P<user>\S+) : .*USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)'
)

TIME_FORMAT = "%b %d %H:%M:%S %Y"


class AuthLogParser:
    def __init__(self, default_year=2026):
        self.default_year = default_year

    def parse_line(self, line):
        prefix = SYSLOG_PREFIX_RE.match(line.strip())
        if not prefix:
            return None

        timestamp = datetime.strptime(f"{prefix.group('time')} {self.default_year}", TIME_FORMAT)
        timestamp = timestamp.replace(tzinfo=timezone.utc)

        process = prefix.group("process")
        message = prefix.group("message")

        if "sshd" in process:
            m = SSH_FAILED_RE.search(message)
            if m:
                return LogEvent(
                    timestamp=timestamp, source="auth", source_ip=m.group("ip"),
                    event_type="ssh_failed_login", user=m.group("user"), status="failed",
                    raw_line=line.strip(), extra={"port": m.group("port")},
                )
            m = SSH_ACCEPTED_RE.search(message)
            if m:
                return LogEvent(
                    timestamp=timestamp, source="auth", source_ip=m.group("ip"),
                    event_type="ssh_accepted_login", user=m.group("user"), status="success",
                    raw_line=line.strip(), extra={"port": m.group("port")},
                )

        if "sudo" in process:
            m = SUDO_RE.search(message)
            if m:
                return LogEvent(
                    timestamp=timestamp, source="auth", source_ip=None,
                    event_type="sudo_command", user=m.group("user"), status="executed",
                    raw_line=line.strip(),
                    extra={"target_user": m.group("target_user"), "command": m.group("command")},
                )

        return None

    def parse_file(self, path):
        events = []
        with open(path, "r") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    events.append(event)
        return events