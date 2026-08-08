"""Defines BaseDetector, the interface every detection rule must implement."""


class BaseDetector:
    def detect(self, events):
        raise NotImplementedError