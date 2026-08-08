"""Runs all registered detectors against a set of events and aggregates their findings."""
from .bruteforce import BruteForceDetector
from .successful_login import SuccessfulLoginAfterFailuresDetector
from .portscan import PortScanDetector
from .unusual_login import UnusualLoginTimeDetector
from .privilege import PrivilegeEscalationDetector


class DetectionEngine:
    def __init__(self):
        self.detectors = [
            BruteForceDetector(),
            SuccessfulLoginAfterFailuresDetector(),
            PortScanDetector(),
            UnusualLoginTimeDetector(),
            PrivilegeEscalationDetector(),
        ]

    def run(self, events):
        findings = []
        for detector in self.detectors:
            findings.extend(detector.detect(events))
        return findings