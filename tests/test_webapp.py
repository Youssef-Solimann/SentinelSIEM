"""Tests for webapp.py's Flask routes, via Flask's test client. No real network calls -- the
impossible-travel checkbox is left unchecked in every test here."""
import io

from webapp import app

AUTH_LOG_LINE = (
    b"Jul 24 09:12:33 webserver sshd[1234]: Failed password for invalid user admin "
    b"from 203.0.113.5 port 51512 ssh2\n"
)


def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_index_shows_upload_form():
    response = client().get("/")

    assert response.status_code == 200
    assert b"SentinelSIEM Dashboard" in response.data
    assert b'name="apache"' in response.data
    assert b'name="nginx"' in response.data
    assert b'name="auth"' in response.data


def test_analyze_without_any_file_returns_error():
    response = client().post("/analyze", data={}, content_type="multipart/form-data")

    assert response.status_code == 400
    assert b"Upload at least one log file" in response.data


def test_analyze_with_auth_log_returns_report():
    data = {"auth": (io.BytesIO(AUTH_LOG_LINE), "auth.log")}
    response = client().post("/analyze", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    assert b"SentinelSIEM Security Report" in response.data
    assert b"Total Events Processed" in response.data
    assert b"New Analysis" in response.data


def test_analyze_merges_multiple_uploaded_sources():
    apache_line = (
        b'192.168.1.15 - - [23/Jul/2026:10:22:31 +0000] "POST /login HTTP/1.1" 401 2326 "-" "Mozilla/5.0"\n'
    )
    data = {
        "apache": (io.BytesIO(apache_line), "apache.log"),
        "auth": (io.BytesIO(AUTH_LOG_LINE), "auth.log"),
    }
    response = client().post("/analyze", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    assert b"Total Events Processed" in response.data
    # 1 apache event + 1 auth event
    assert b">2<" in response.data
