"""Renders a self-contained static HTML security report from events and findings."""
from datetime import datetime, timezone

from jinja2 import Template

from models.severity import Severity
from reports.attack import get_technique
from reports.stats import build_summary

SEVERITY_COLORS = {
    Severity.CRITICAL: "#f85149",
    Severity.HIGH: "#f0883e",
    Severity.MEDIUM: "#e3b341",
    Severity.LOW: "#58a6ff",
}

CHART_ROW_HEIGHT = 28
CHART_BAR_HEIGHT = 18
CHART_MAX_BAR_WIDTH = 200
CHART_LABEL_WIDTH = 70

REPORT_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelSIEM Security Report</title>
<style>
    body {
        margin: 0;
        padding: 2.5rem;
        background: #0d1117;
        color: #c9d1d9;
        font-family: "Segoe UI", Helvetica, Arial, sans-serif;
        line-height: 1.5;
    }
    h1 {
        color: #f0f6fc;
        font-size: 1.6rem;
        margin-bottom: 0.25rem;
    }
    .subtitle {
        color: #8b949e;
        margin-bottom: 0.25rem;
    }
    .meta {
        color: #8b949e;
        font-size: 0.85rem;
        margin-bottom: 2rem;
    }
    h2 {
        color: #f0f6fc;
        font-size: 1.15rem;
        border-bottom: 1px solid #21262d;
        padding-bottom: 0.5rem;
        margin-top: 2.5rem;
    }
    .tiles {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
        margin: 1.25rem 0;
    }
    .tile {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        min-width: 140px;
    }
    .tile .label {
        color: #8b949e;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .tile .value {
        font-size: 1.6rem;
        font-weight: 600;
        color: #f0f6fc;
        margin-top: 0.25rem;
    }
    .badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 600;
        color: #0d1117;
    }
    .chart-wrap {
        margin: 1.25rem 0 2rem;
    }
    .toolbar {
        margin: 1rem 0;
    }
    #finding-search {
        width: 100%;
        max-width: 420px;
        padding: 0.5rem 0.75rem;
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        color: #c9d1d9;
        font-size: 0.9rem;
    }
    #finding-search:focus {
        outline: none;
        border-color: #58a6ff;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
        font-size: 0.9rem;
    }
    th, td {
        text-align: left;
        padding: 0.6rem 0.75rem;
        border-bottom: 1px solid #21262d;
        vertical-align: top;
    }
    th {
        color: #8b949e;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.03em;
    }
    thead th {
        position: sticky;
        top: 0;
        background: #0d1117;
    }
    th[data-sort-key] {
        cursor: pointer;
        user-select: none;
    }
    th[data-sort-key]:hover {
        color: #f0f6fc;
    }
    th.sort-asc::after {
        content: " \\2191";
    }
    th.sort-desc::after {
        content: " \\2193";
    }
    tr.finding-row {
        cursor: pointer;
        transition: background-color 0.15s ease;
    }
    tr.finding-row:hover {
        background: #1c2333;
    }
    tr.detail-row td {
        border-bottom: 1px solid #21262d;
        padding: 0;
    }
    .hidden-row {
        display: none;
    }
    .chevron {
        display: inline-block;
        margin-right: 0.5rem;
        color: #8b949e;
        transition: transform 0.15s ease;
    }
    tr.finding-row.expanded .chevron {
        transform: rotate(90deg);
    }
    .evidence {
        padding: 0.75rem 1rem 1rem 2.25rem;
    }
    .evidence pre {
        background: #010409;
        border: 1px solid #21262d;
        border-radius: 6px;
        padding: 0.6rem 0.8rem;
        margin: 0.35rem 0;
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 0.8rem;
        color: #8b949e;
        overflow-x: auto;
        white-space: pre;
    }
    .ip {
        font-family: "SFMono-Regular", Consolas, monospace;
    }
    .timestamp {
        font-family: "SFMono-Regular", Consolas, monospace;
        color: #8b949e;
        white-space: nowrap;
    }
    .attack {
        color: #8b949e;
        white-space: nowrap;
    }
    .empty {
        color: #8b949e;
        font-style: italic;
    }
    .rank {
        color: #8b949e;
        display: inline-block;
        width: 1.5rem;
    }
</style>
</head>
<body>

<h1>SentinelSIEM Security Report</h1>
<div class="subtitle">Automated log analysis and threat detection summary</div>
<div class="meta">Report generated at {{ generated_at }}</div>

<h2>Executive Summary</h2>
<div class="tiles">
    <div class="tile">
        <div class="label">Total Events Processed</div>
        <div class="value">{{ summary.total_events }}</div>
    </div>
    <div class="tile">
        <div class="label">Total Findings</div>
        <div class="value">{{ summary.total_findings }}</div>
    </div>
</div>

<div class="tiles">
    {% for row in severity_rows %}
    <div class="tile">
        <div class="label">{{ row.severity }}</div>
        <div class="value"><span class="badge" style="background: {{ row.color }};">{{ row.count }}</span></div>
    </div>
    {% else %}
    <div class="empty">No findings, so no severity breakdown to show.</div>
    {% endfor %}
</div>

<div class="chart-wrap">
    {% if chart_rows %}
    <svg viewBox="0 0 300 {{ chart_height }}" width="100%" style="max-width: 340px; height: {{ chart_height }}px;" role="img" aria-label="Findings by severity">
        {% for row in chart_rows %}
        <text x="0" y="{{ row.y + 14 }}" fill="#c9d1d9" font-size="12">{{ row.severity }}</text>
        <rect x="{{ 70 }}" y="{{ row.y }}" width="{{ row.bar_width }}" height="18" rx="3" fill="{{ row.color }}"></rect>
        <text x="{{ row.label_x }}" y="{{ row.y + 14 }}" fill="#c9d1d9" font-size="12">{{ row.count }}</text>
        {% endfor %}
    </svg>
    {% else %}
    <p class="empty">No findings, so no severity chart to show.</p>
    {% endif %}
</div>

<h2>Top Attacking IPs</h2>
{% if top_ips %}
<table>
    <thead>
        <tr><th>Rank</th><th>Source IP</th><th>Finding Count</th></tr>
    </thead>
    <tbody>
        {% for ip, count in top_ips %}
        <tr>
            <td class="rank">{{ loop.index }}</td>
            <td class="ip">{{ ip }}</td>
            <td>{{ count }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<p class="empty">No source IPs associated with any findings.</p>
{% endif %}

<h2>Full Findings</h2>
<div class="toolbar">
    <input type="text" id="finding-search" placeholder="Filter by title, source IP, description, or ATT&amp;CK technique..." autocomplete="off">
</div>
{% if finding_rows %}
<table id="findings-table">
    <thead>
        <tr>
            <th data-sort-key="title">Title</th>
            <th data-sort-key="severity">Severity</th>
            <th data-sort-key="ip">Source IP</th>
            <th data-sort-key="timestamp">Timestamp</th>
            <th data-sort-key="attack">ATT&amp;CK Technique</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        {% for row in finding_rows %}
        <tr class="finding-row"
            data-title="{{ row.title }}"
            data-severity="{{ row.severity_rank }}"
            data-ip="{{ row.source_ip }}"
            data-timestamp="{{ row.timestamp }}"
            data-attack="{{ row.attack_label }}"
            data-search="{{ row.search_blob }}">
            <td><span class="chevron">&#9656;</span>{{ row.title }}</td>
            <td><span class="badge" style="background: {{ row.color }};">{{ row.severity }}</span></td>
            <td class="ip">{{ row.source_ip }}</td>
            <td class="timestamp">{{ row.timestamp }}</td>
            <td class="attack">{{ row.attack_label }}</td>
            <td>{{ row.description }}</td>
        </tr>
        <tr class="detail-row hidden-row">
            <td colspan="6">
                <div class="evidence">
                    {% if row.evidence %}
                        {% for line in row.evidence %}
                        <pre>{{ line }}</pre>
                        {% endfor %}
                    {% else %}
                        <p class="empty">No evidence recorded.</p>
                    {% endif %}
                </div>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<p class="empty">No findings were detected in this run.</p>
{% endif %}

<script>
(function () {
    var table = document.getElementById('findings-table');
    if (!table) { return; }
    var tbody = table.querySelector('tbody');
    var headers = Array.prototype.slice.call(table.querySelectorAll('th[data-sort-key]'));
    var sortState = { key: null, asc: true };

    function rowGroups() {
        var mains = Array.prototype.slice.call(tbody.querySelectorAll('tr.finding-row'));
        return mains.map(function (row) {
            return { main: row, detail: row.nextElementSibling };
        });
    }

    headers.forEach(function (th) {
        th.addEventListener('click', function () {
            var key = th.getAttribute('data-sort-key');
            var asc = sortState.key === key ? !sortState.asc : true;
            sortState = { key: key, asc: asc };

            headers.forEach(function (h) { h.classList.remove('sort-asc', 'sort-desc'); });
            th.classList.add(asc ? 'sort-asc' : 'sort-desc');

            var groups = rowGroups();
            groups.sort(function (a, b) {
                var av = a.main.getAttribute('data-' + key) || '';
                var bv = b.main.getAttribute('data-' + key) || '';
                var cmp;
                if (key === 'severity') {
                    cmp = Number(av) - Number(bv);
                } else {
                    cmp = av.toLowerCase().localeCompare(bv.toLowerCase());
                }
                return asc ? cmp : -cmp;
            });

            groups.forEach(function (g) {
                tbody.appendChild(g.main);
                if (g.detail) { tbody.appendChild(g.detail); }
            });
        });
    });

    rowGroups().forEach(function (g) {
        g.main.addEventListener('click', function () {
            if (!g.detail) { return; }
            var expanded = g.main.classList.toggle('expanded');
            g.detail.classList.toggle('hidden-row', !expanded);
        });
    });

    var search = document.getElementById('finding-search');
    if (search) {
        search.addEventListener('input', function () {
            var q = search.value.trim().toLowerCase();
            rowGroups().forEach(function (g) {
                var haystack = g.main.getAttribute('data-search') || '';
                var match = haystack.indexOf(q) !== -1;
                g.main.classList.toggle('hidden-row', !match);
                if (!g.detail) { return; }
                if (!match) {
                    g.detail.classList.add('hidden-row');
                } else if (g.main.classList.contains('expanded')) {
                    g.detail.classList.remove('hidden-row');
                }
            });
        });
    }
})();
</script>

</body>
</html>
""", autoescape=True)


def _build_chart_rows(severity_rows):
    if not severity_rows:
        return []

    max_count = max(row["count"] for row in severity_rows)
    chart_rows = []
    for index, row in enumerate(severity_rows):
        bar_width = max(4, round((row["count"] / max_count) * CHART_MAX_BAR_WIDTH))
        y = index * CHART_ROW_HEIGHT
        chart_rows.append({
            "severity": row["severity"],
            "count": row["count"],
            "color": row["color"],
            "y": y,
            "bar_width": bar_width,
            "label_x": CHART_LABEL_WIDTH + bar_width + 8,
        })
    return chart_rows


def generate_report(events, findings, output_path="report.html"):
    summary = build_summary(events, findings)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    severity_rows = [
        {"severity": severity, "count": count, "color": SEVERITY_COLORS.get(severity, "#8b949e")}
        for severity, count in sorted(summary["by_severity"].items(), reverse=True)
    ]
    chart_rows = _build_chart_rows(severity_rows)
    chart_height = len(chart_rows) * CHART_ROW_HEIGHT + 6

    finding_rows = []
    for finding in findings:
        source_ip = finding.source_ip if finding.source_ip is not None else "—"
        technique = get_technique(finding)
        attack_label = f"{technique['technique_id']} - {technique['technique_name']}" if technique else "—"
        search_blob = f"{finding.title} {source_ip} {finding.description} {attack_label}".lower()
        finding_rows.append({
            "title": finding.title,
            "severity": finding.severity,
            "severity_rank": int(finding.severity),
            "color": SEVERITY_COLORS.get(finding.severity, "#8b949e"),
            "source_ip": source_ip,
            "timestamp": finding.timestamp,
            "attack_label": attack_label,
            "description": finding.description,
            "search_blob": search_blob,
            "evidence": [event.raw_line for event in finding.evidence],
        })

    html = REPORT_TEMPLATE.render(
        summary=summary,
        severity_rows=severity_rows,
        chart_rows=chart_rows,
        chart_height=chart_height,
        top_ips=summary["top_ips"],
        finding_rows=finding_rows,
        generated_at=generated_at,
    )

    with open(output_path, "w") as f:
        f.write(html)

    return output_path
