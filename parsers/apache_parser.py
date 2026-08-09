"""Parses Apache combined-format access log lines into normalized LogEvent objects."""
import re
from datetime import datetime
from .base import LogEvent

APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ApacheLogParser:
    def parse_line(self, line):
        match = APACHE_RE.match(line.strip())
        if not match:
            return None
        d = match.groupdict()
        timestamp = datetime.strptime(d["time"], TIME_FORMAT)
        user = None if d["user"] == "-" else d["user"]

        return LogEvent(
            timestamp=timestamp,
            source="apache",
            source_ip=d["ip"],
            event_type="http_request",
            user=user,
            status=d["status"],
            raw_line=line.strip(),
            extra={
                "method": d["method"],
                "path": d["path"],
                "protocol": d["protocol"],
                "size": d["size"],
                "referer": d["referer"],
                "agent": d["agent"],
            },
        )

    def parse_file(self, path):
        events = []
        with open(path, "r") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    events.append(event)
        return events