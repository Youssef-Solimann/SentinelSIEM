"""Flask dashboard: upload log files, run the same detection pipeline as main.py, view the report live in the browser."""
import os
import tempfile
from datetime import datetime

from flask import Flask, Response, render_template, request

from parsers.apache_parser import ApacheLogParser
from parsers.nginx_parser import NginxLogParser
from parsers.auth_parser import AuthLogParser
from detectors.engine import DetectionEngine
from detectors.impossible_travel import ImpossibleTravelDetector
from reports.html import generate_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB per request

BACK_LINK_HTML = (
    '<div style="padding: 0 2.5rem; margin-top: 1.5rem;">'
    '<a href="/" style="color:#58a6ff; text-decoration:none; font-size:0.9rem;">&larr; New Analysis</a></div>'
)


def _has_any_upload():
    for field in ("apache", "nginx", "auth"):
        file_storage = request.files.get(field)
        if file_storage and file_storage.filename:
            return True
    return False


def _collect_events(tmpdir):
    events = []
    current_year = datetime.now().year

    apache_file = request.files.get("apache")
    if apache_file and apache_file.filename:
        path = os.path.join(tmpdir, "apache.log")
        apache_file.save(path)
        events.extend(ApacheLogParser().parse_file(path))

    nginx_file = request.files.get("nginx")
    if nginx_file and nginx_file.filename:
        path = os.path.join(tmpdir, "nginx.log")
        nginx_file.save(path)
        events.extend(NginxLogParser().parse_file(path))

    auth_file = request.files.get("auth")
    if auth_file and auth_file.filename:
        path = os.path.join(tmpdir, "auth.log")
        auth_file.save(path)
        events.extend(AuthLogParser(default_year=current_year).parse_file(path))

    return events


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", error=None)


@app.route("/analyze", methods=["POST"])
def analyze():
    if not _has_any_upload():
        return render_template(
            "index.html",
            error="Upload at least one log file (Apache, Nginx, or auth.log).",
        ), 400

    with tempfile.TemporaryDirectory() as tmpdir:
        events = _collect_events(tmpdir)

        findings = DetectionEngine().run(events)
        if request.form.get("impossible_travel"):
            findings += ImpossibleTravelDetector().detect(events)

        report_path = os.path.join(tmpdir, "report.html")
        generate_report(events, findings, report_path)

        with open(report_path, "r") as f:
            html = f.read()

    html = html.replace("<body>", "<body>\n" + BACK_LINK_HTML, 1)
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(debug=False)
