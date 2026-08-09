# SentinelSIEM 🛡️

> A lightweight SIEM-inspired log analysis and threat detection engine built in Python. SentinelSIEM parses logs from multiple sources, normalizes them into a common event model, detects suspicious activity using rule-based analytics, and generates investigation-ready security reports.

---

## Status

🚧 **Active Development**

Current Progress:

- ✅ Phase 1 — Log Parsing
- ✅ Phase 2 — Detection Engine
- ✅ Phase 3 — Severity Classification (basic)
- ✅ Phase 4 — Reporting

---

## Goals

SentinelSIEM is designed to demonstrate the core concepts behind a Security Information and Event Management (SIEM) platform by:

- Parsing logs from multiple sources.
- Normalizing different log formats into a unified event model.
- Detecting suspicious activity using modular detection rules.
- Classifying findings by severity.
- Generating investigation-ready security reports.

---

## Features

### ✅ Log Parsing

Currently supported:

- Apache access logs
- Nginx access logs
- Linux authentication (`auth.log`) logs
  - Failed SSH logins
  - Successful SSH logins
  - `sudo` commands

All parsers normalize their output into a common `LogEvent` schema.

This allows every detector to analyze events without needing to know whether they originated from Apache, Nginx, or Linux authentication logs.

### ✅ Detection Engine

`DetectionEngine` runs every detector below against a combined list of `LogEvent`s and aggregates the results into `Finding` objects:

- SSH brute-force detection — repeated failed SSH logins from one IP within a time window
- Successful login after multiple failures — a login that succeeds right after a failure burst from the same IP
- Port/path scan detection — many distinct paths requested by one IP in a short window
- Unusual login time detection — successful logins outside configured business hours
- Privilege escalation detection — `sudo` commands containing sensitive keywords (`shadow`, `useradd`, `passwd`, `chmod 777`, `visudo`), matched case-insensitively

### ✅ Severity Classification

Findings are labeled using a shared `Severity` enum (`models/severity.py`), so every detector draws from the same vocabulary instead of ad-hoc strings:

- Critical
- High
- Medium
- Low

`Severity` is an `IntEnum`, so findings can be compared/sorted by severity (`Severity.HIGH > Severity.LOW`), and it prints as a lowercase name (`str(Severity.HIGH) == "high"`).

### ✅ Reporting

- `reports/stats.py` — severity counts, top attacking IPs, most common finding types, and an aggregated `build_summary()` used by both the HTML report and the CLI.
- `reports/html.py` — a single self-contained, dark-themed HTML report (inline CSS/JS, no external dependencies, works fully offline):
  - Executive summary tiles and an inline SVG severity bar chart
  - Sortable findings table (click a column header, click again to reverse), including a MITRE ATT&CK Technique column
  - Real-time search/filter across title, source IP, description, and ATT&CK technique
  - Expandable rows revealing the raw evidence log lines behind each finding
  - Rendered with Jinja2 autoescaping on, so log-derived content (attacker-controlled paths, usernames, commands) can't inject HTML/JS into the report
- `reports/attack.py` — a static lookup table mapping each finding title to a MITRE ATT&CK technique ID, name, and tactic. Not every finding maps to a precise technique (e.g. "Login Outside Business Hours" is a behavioral heuristic, not a listed technique) — those are tagged with the closest reasonable fit rather than forcing false precision.
- `reports/ioc.py` — extracts indicators of compromise (source IPs) from findings, aggregating finding count, severities, associated ATT&CK techniques, and first/last-seen timestamps per IP, exportable as JSON via `--iocs`.
- `main.py` — CLI entry point that ties parsing, detection, HTML reporting, and IOC export into one command (see [Usage](#usage)).

---

## Deferred / v2

### Future Enhancements

- Threat intelligence integration (AbuseIPDB / AlienVault OTX)
- Geo-IP enrichment
- Impossible travel detection
- Flask dashboard
- Interactive visualizations
- Real-time log monitoring

---

## Architecture

```text
                    Raw Log Files
                          │
                          ▼
                    Log Parsers
                          │
                          ▼
              Standardized LogEvents
                          │
                          ▼
                 Detection Engine
                          │
                          ▼
                     Findings
                          │
                          ▼
                Severity Assignment
                          │
                          ▼
              Statistics & HTML Report
```

---

## Project Structure

```text
SentinelSIEM/
│
├── parsers/
│   ├── base.py           # LogEvent model
│   ├── apache_parser.py
│   ├── nginx_parser.py
│   └── auth_parser.py
│
├── models/
│   ├── finding.py         # Finding model
│   └── severity.py        # Severity enum
│
├── detectors/
│   ├── base.py             # BaseDetector interface
│   ├── engine.py           # DetectionEngine — runs all detectors
│   ├── bruteforce.py
│   ├── successful_login.py
│   ├── portscan.py
│   ├── unusual_login.py
│   └── privilege.py
│
├── reports/
│   ├── stats.py            # summary statistics (severity counts, top IPs, etc.)
│   ├── html.py             # self-contained HTML report generator
│   ├── attack.py           # finding title -> MITRE ATT&CK technique mapping
│   └── ioc.py               # indicator of compromise extraction + JSON export
│
├── rules/                  # planned: configurable detection rules
│
├── sample_logs/
│   ├── apache_access.log
│   ├── nginx_access.log
│   └── auth.log
│
├── tests/
│   ├── helpers.py           # LogEvent/Finding factory helpers for tests
│   ├── test_apache_parser.py
│   ├── test_nginx_parser.py
│   ├── test_auth_parser.py
│   ├── test_bruteforce.py
│   ├── test_successful_login.py
│   ├── test_portscan.py
│   ├── test_unusual_login.py
│   ├── test_privilege.py
│   ├── test_engine.py
│   ├── test_stats.py
│   ├── test_attack.py
│   └── test_ioc.py
│
├── main.py                  # CLI entry point
│
├── requirements.txt
│
└── README.md
```

---

## Example Workflow

```text
Apache Log
       │
       ▼
Apache Parser
       │
       ▼
LogEvent
       │
       ▼
Detection Engine
       │
       ▼
Finding
       │
       ▼
HTML Report
```

---

## Example Input

```text
192.168.1.15 - - [23/Jul/2026:10:22:31 +0000] "POST /login HTTP/1.1" 401 2326 "-" "Mozilla/5.0"
```

↓

```python
LogEvent(
    timestamp=datetime(...),
    source="apache",
    source_ip="192.168.1.15",
    event_type="http_request",
    status="401",
    user=None,
)
```

---

## Usage

Run the CLI entry point with one or more log files. At least one of `--apache`, `--nginx`, or `--auth` is required; `--output` defaults to `report.html`.

```bash
python main.py --auth sample_logs/auth.log --nginx sample_logs/nginx_access.log --apache sample_logs/apache_access.log --output report.html --iocs iocs.json
```

This parses the provided logs, runs `DetectionEngine`, writes the HTML report to `--output`, and prints a console summary (total events, total findings, findings by severity, and the output path). A path that doesn't exist is reported and skipped rather than crashing the run. `--iocs` is optional — if provided, it also writes a JSON file of indicators of compromise (source IPs, with finding counts, severities, associated MITRE ATT&CK techniques, and first/last-seen timestamps).

### Programmatic Usage

```python
from parsers.apache_parser import ApacheLogParser
from parsers.nginx_parser import NginxLogParser
from parsers.auth_parser import AuthLogParser
from detectors.engine import DetectionEngine

apache_events = ApacheLogParser().parse_file("sample_logs/apache_access.log")
nginx_events = NginxLogParser().parse_file("sample_logs/nginx_access.log")
auth_events = AuthLogParser(default_year=2026).parse_file("sample_logs/auth.log")

events = apache_events + nginx_events + auth_events

findings = DetectionEngine().run(events)

for finding in findings:
    print(f"[{finding.severity}] {finding.title} — {finding.description}")
```

---

## Testing

```bash
pytest
```

67 tests covering all three parsers (valid/malformed lines, timezone handling), all five detectors (empty input, exact-threshold boundaries, time-window edges, out-of-order input, evidence non-duplication), `DetectionEngine` aggregation, and the `reports/` modules (`stats.py`, `attack.py`, `ioc.py`). Tests build synthetic `LogEvent`/`Finding` objects directly (via `tests/helpers.py`) rather than depending on the sample log files, so they stay fast and isolated from parser changes.

---

## Detection Rules

| Detection | Description |
|-----------|-------------|
| SSH Brute Force | Multiple failed login attempts from the same IP within a configurable time window |
| Successful Login After Failures | Detects a successful authentication following repeated failures |
| Port Scan | Detects rapid requests to many different endpoints from a single IP |
| Unusual Login Time | Flags logins occurring outside expected operating hours |
| Privilege Escalation | Detects suspicious `sudo` activity and privilege-related events |

---

## Roadmap

### Phase 1 — Log Parsing

- [x] Apache parser
- [x] Nginx parser
- [x] Linux authentication parser

### Phase 2 — Detection Engine

- [x] SSH brute-force detector
- [x] Port scan detector
- [x] Successful login after failures
- [x] Unusual login detector
- [x] Privilege escalation detector
- [x] `DetectionEngine` to run all detectors and aggregate findings

### Phase 3 — Severity

- [x] Severity scoring (fixed per-rule levels via a shared `Severity` enum)
- [x] Finding model

### Phase 4 — Reporting

- [x] Findings report (`reports/stats.py`)
- [x] Statistics (`reports/stats.py`)
- [x] Self-contained HTML report (`reports/html.py`)
- [x] MITRE ATT&CK mapping (`reports/attack.py`)
- [x] IOC export (JSON) (`reports/ioc.py`)
- [x] CLI entry point tying the pipeline together (`main.py`)

### Phase 5 — Future Enhancements

- [ ] Threat intelligence integration
- [ ] Geo-IP enrichment
- [ ] Impossible travel detection
- [ ] Flask dashboard
- [ ] Visualizations

---

## Technologies

- Python 3
- Regular Expressions (`re`)
- `datetime`
- HTML/CSS/vanilla JS (inline SVG charts, sortable/filterable report table)
- Jinja2
- pytest
- Flask *(optional, planned for a future dashboard)*
- YAML *(planned for configurable rules)*

---

## Learning Objectives

This project demonstrates practical experience with:

- Security Information and Event Management (SIEM)
- Log parsing and normalization
- Detection engineering
- Rule-based threat detection
- Security event correlation
- Incident response fundamentals
- Python software architecture
- Blue Team methodologies

---

## Contributing

This repository is primarily a personal learning project. Suggestions, improvements, and feedback are always welcome.

---

## License

This project is licensed under the MIT License.