from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from parsers.base import LogEvent


@dataclass
class Finding:
    title: str
    severity: str
    event_type: str
    source_ip: Optional[str]
    timestamp: datetime
    description: str
    evidence: list = field(default_factory=list)