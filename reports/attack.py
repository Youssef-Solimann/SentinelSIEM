"""Maps finding titles to MITRE ATT&CK techniques for context in reports and IOC exports."""

# Not every finding maps to a distinct technique. "Login Outside Business Hours" is a
# behavioral heuristic, not a listed ATT&CK technique -- it's tagged with the closest
# fit (Valid Accounts) rather than a precise match.
ATTACK_MAPPING = {
    "SSH Brute Force Detected": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "Successful Login After Repeated Failures": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
    },
    "Possible Port/Path Scan Detected": {
        "technique_id": "T1595.003",
        "technique_name": "Active Scanning: Wordlist Scanning",
        "tactic": "Reconnaissance",
    },
    "Login Outside Business Hours": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
    },
    "Suspicious Privilege Escalation Command": {
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
    },
    "Impossible Travel Detected": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
    },
}


def get_technique(finding):
    return ATTACK_MAPPING.get(finding.title)
