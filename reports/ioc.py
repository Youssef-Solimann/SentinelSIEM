"""Extracts indicators of compromise (source IPs) from findings and exports them as JSON."""
import json

from reports.attack import get_technique


def build_iocs(findings):
    iocs = {}
    for finding in findings:
        if finding.source_ip is None:
            continue

        ioc = iocs.setdefault(finding.source_ip, {
            "indicator": finding.source_ip,
            "type": "ip",
            "finding_count": 0,
            "finding_titles": set(),
            "severities": set(),
            "attack_techniques": set(),
            "first_seen": finding.timestamp,
            "last_seen": finding.timestamp,
        })

        ioc["finding_count"] += 1
        ioc["finding_titles"].add(finding.title)
        ioc["severities"].add(str(finding.severity))

        technique = get_technique(finding)
        if technique:
            ioc["attack_techniques"].add(f"{technique['technique_id']} - {technique['technique_name']}")

        if finding.timestamp < ioc["first_seen"]:
            ioc["first_seen"] = finding.timestamp
        if finding.timestamp > ioc["last_seen"]:
            ioc["last_seen"] = finding.timestamp

    results = [
        {
            "indicator": ioc["indicator"],
            "type": ioc["type"],
            "finding_count": ioc["finding_count"],
            "finding_titles": sorted(ioc["finding_titles"]),
            "severities": sorted(ioc["severities"]),
            "attack_techniques": sorted(ioc["attack_techniques"]),
            "first_seen": ioc["first_seen"].isoformat(),
            "last_seen": ioc["last_seen"].isoformat(),
        }
        for ioc in iocs.values()
    ]

    results.sort(key=lambda entry: entry["finding_count"], reverse=True)
    return results


def export_iocs_json(findings, output_path="iocs.json"):
    iocs = build_iocs(findings)
    with open(output_path, "w") as f:
        json.dump(iocs, f, indent=2)
    return iocs
