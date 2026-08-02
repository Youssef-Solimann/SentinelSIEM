# SentinelSIEM 🛡️

> A lightweight SIEM-inspired log analysis and threat detection engine built in Python. SentinelSIEM parses logs from multiple sources, normalizes them into a common event model, detects suspicious activity using rule-based analytics, and generates investigation-ready security reports.

---

## Status

🚧 **Active Development**

Current Progress:

- ✅ Phase 1 — Log Parsing
- 🚧 Phase 2 — Detection Engine
- ⏳ Phase 3 — Severity Classification
- ⏳ Phase 4 — Reporting

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

---

## Planned Features

### Threat Detection

- SSH brute-force detection
- Successful login after multiple failures
- Port scan detection
- Unusual login time detection
- Privilege escalation indicators

### Severity Classification

- Critical
- High
- Medium
- Low
- Informational

### Reporting

- Detailed findings report
- Security statistics
- Self-contained HTML report
- IOC export (JSON)
- MITRE ATT&CK mapping

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
│   ├── base.py
│   ├── apache_parser.py
│   ├── nginx_parser.py
│   └── auth_parser.py
│
├── detectors/
│   ├── bruteforce.py
│   ├── portscan.py
│   ├── privilege.py
│   └── unusual_login.py
│
├── rules/
│
├── reports/
│
├── templates/
│
├── sample_logs/
│
├── tests/
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
    status=401,
    user=None,
)
```

---

## Usage

```python
from parsers.apache_parser import ApacheLogParser
from parsers.nginx_parser import NginxLogParser
from parsers.auth_parser import AuthLogParser

apache_events = ApacheLogParser().parse_file(
    "sample_logs/apache_access.log"
)

nginx_events = NginxLogParser().parse_file(
    "sample_logs/nginx_access.log"
)

auth_events = AuthLogParser(default_year=2026).parse_file(
    "sample_logs/auth.log"
)

events = apache_events + nginx_events + auth_events
```

The resulting `events` list can then be passed to the detection engine for analysis.

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

- [ ] SSH brute-force detector
- [ ] Port scan detector
- [ ] Successful login after failures
- [ ] Unusual login detector
- [ ] Privilege escalation detector

### Phase 3 — Severity

- [ ] Severity scoring
- [ ] Finding model

### Phase 4 — Reporting

- [ ] Findings report
- [ ] Statistics
- [ ] HTML report
- [ ] IOC export
- [ ] MITRE ATT&CK mapping

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
- HTML/CSS
- Jinja2 *(planned)*
- Flask *(optional)*
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