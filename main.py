"""CLI entry point that runs the full pipeline: parse logs, detect threats, generate an HTML report."""
import argparse
import os
from datetime import datetime

from parsers.apache_parser import ApacheLogParser
from parsers.nginx_parser import NginxLogParser
from parsers.auth_parser import AuthLogParser
from detectors.engine import DetectionEngine
from detectors.impossible_travel import ImpossibleTravelDetector
from reports.html import generate_report
from reports.ioc import export_iocs_json
from reports.stats import build_summary


def parse_args():
    parser = argparse.ArgumentParser(
        description="SentinelSIEM -- parse logs, run threat detection, and generate an HTML security report.",
        epilog=(
            "Example:\n"
            "  python main.py --auth sample_logs/auth.log "
            "--nginx sample_logs/nginx_access.log "
            "--apache sample_logs/apache_access.log "
            "--iocs iocs.json"
        ),

        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--apache", metavar="PATH", help="path to an Apache access log file")
    parser.add_argument("--nginx", metavar="PATH", help="path to an Nginx access log file")
    parser.add_argument("--auth", metavar="PATH", help="path to a Linux auth.log file")
    parser.add_argument(
        "--output", metavar="PATH", default="report.html",
        help="where to write the HTML report (default: report.html)",
    )
    parser.add_argument(
        "--iocs", metavar="PATH",
        help="optional: also export indicators of compromise (source IPs) as JSON to this path",
    )
    parser.add_argument(
        "--impossible-travel", action="store_true",
        help=(
            "optional: also run ImpossibleTravelDetector. Requires network access -- "
            "queries the free ip-api.com service (plain HTTP, no API key) to geolocate source IPs"
        ),
    )

    args = parser.parse_args()

    if not (args.apache or args.nginx or args.auth):
        parser.error("at least one of --apache, --nginx, --auth must be provided")

    return args


def collect_events(args):
    events = []
    current_year = datetime.now().year

    if args.apache:
        if os.path.exists(args.apache):
            events.extend(ApacheLogParser().parse_file(args.apache))
        else:
            print(f"Error: Apache log not found, skipping: {args.apache}")

    if args.nginx:
        if os.path.exists(args.nginx):
            events.extend(NginxLogParser().parse_file(args.nginx))
        else:
            print(f"Error: Nginx log not found, skipping: {args.nginx}")

    if args.auth:
        if os.path.exists(args.auth):
            events.extend(AuthLogParser(default_year=current_year).parse_file(args.auth))
        else:
            print(f"Error: auth log not found, skipping: {args.auth}")

    return events


def print_summary(summary, output_path, iocs_path=None, ioc_count=None):
    print()
    print(f"Total events processed: {summary['total_events']}")
    print(f"Total findings: {summary['total_findings']}")
    print("Findings by severity:")
    if summary["by_severity"]:
        for severity, count in sorted(summary["by_severity"].items(), reverse=True):
            print(f"  {severity}: {count}")
    else:
        print("  (none)")
    print(f"Report written to: {output_path}")
    if iocs_path is not None:
        print(f"IOCs exported: {ioc_count} -> {iocs_path}")


def main():
    args = parse_args()
    events = collect_events(args)

    if not events:
        print("Warning: no events were parsed from the provided log file(s).")

    findings = DetectionEngine().run(events)
    if args.impossible_travel:
        print("Note: --impossible-travel makes external geo-IP lookups (ip-api.com)")
        findings += ImpossibleTravelDetector().detect(events)

    generate_report(events, findings, args.output)

    ioc_count = None
    if args.iocs:
        ioc_count = len(export_iocs_json(findings, args.iocs))

    summary = build_summary(events, findings)
    print_summary(summary, args.output, args.iocs, ioc_count)


if __name__ == "__main__":
    main()
