"""Defines Finding, the standardized output produced by every detector."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from models.severity import Severity


@dataclass
class Finding:
    title: str
    severity: "Severity"
    event_type: str
    source_ip: Optional[str]
    timestamp: datetime
    description: str
    evidence: list = field(default_factory=list)
    geo_context: Optional[list] = None