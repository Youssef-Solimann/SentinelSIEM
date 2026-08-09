"""Detects sudo commands containing keywords associated with privilege escalation."""
from .base import BaseDetector
from models.finding import Finding
from models.severity import Severity
from rules.loader import get_section

_RULES = get_section("privilege")
DANGEROUS_COMMAND_KEYWORDS = _RULES.get(
    "dangerous_keywords", ["shadow", "useradd", "passwd", "chmod 777", "visudo"]
)


class PrivilegeEscalationDetector(BaseDetector):
    def detect(self, events):
        findings = []

        sudo_events = [e for e in events if e.event_type == "sudo_command"]

        for event in sudo_events:
            command = event.extra.get("command", "").lower()
            matched = [kw for kw in DANGEROUS_COMMAND_KEYWORDS if kw in command]

            if matched:
                findings.append(Finding(
                    title="Suspicious Privilege Escalation Command",
                    severity=Severity.CRITICAL,
                    event_type="sudo_command",
                    source_ip=event.source_ip,
                    timestamp=event.timestamp,
                    description=(
                        f"'{event.user}' ran a sensitive command as "
                        f"'{event.extra.get('target_user')}': {command}"
                    ),
                    evidence=[event],
                ))

        return findings