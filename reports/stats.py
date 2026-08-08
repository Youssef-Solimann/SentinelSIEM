"""Computes summary statistics from Finding and LogEvent collections."""


def count_by_severity(findings):
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def top_attacking_ip(findings, limit=5):
    counts = {}
    for finding in findings:
        if finding.source_ip is None:
            continue
        counts[finding.source_ip] = counts.get(finding.source_ip, 0) + 1

    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return ranked[:limit]


def most_common_finding_type(findings):
    counts = {}
    for finding in findings:
        counts[finding.title] = counts.get(finding.title, 0) + 1

    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


def total_events_processed(events):
    return len(events)


def build_summary(events, findings):
    return {
        "total_events": total_events_processed(events),
        "total_findings": len(findings),
        "by_severity": count_by_severity(findings),
        "top_ips": top_attacking_ip(findings),
        "top_finding_types": most_common_finding_type(findings),
    }
