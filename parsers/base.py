"""Defines LogEvent, the normalized representation all parsers produce."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    source_ip: Optional[str]
    event_type: str
    user: Optional[str] = None
    status: Optional[str] = None
    raw_line: str = ""
    extra: dict = field(default_factory=dict)

