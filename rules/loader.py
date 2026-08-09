"""Loads detector thresholds from rules/config.yaml, falling back to {} if missing or invalid."""
import os

import yaml

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")


def load_rules():
    try:
        with open(CONFIG_PATH, "r") as f:
            data = yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError):
        return {}
    return data or {}


def get_section(name):
    return load_rules().get(name, {})
