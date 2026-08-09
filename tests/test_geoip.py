"""Tests for reports/geoip.py. All network calls are mocked -- no real HTTP requests."""
import json
import urllib.error
from unittest.mock import MagicMock, patch

from reports.geoip import lookup_ip


def _mock_response(payload):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(payload).encode()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def test_successful_lookup_returns_geo_dict():
    payload = {"status": "success", "country": "United States", "city": "Ashburn", "lat": 39.03, "lon": -77.47}
    with patch("reports.geoip.urllib.request.urlopen", return_value=_mock_response(payload)):
        result = lookup_ip("8.8.8.8")

    assert result == {"country": "United States", "city": "Ashburn", "lat": 39.03, "lon": -77.47}


def test_fail_status_returns_none():
    payload = {"status": "fail", "message": "private range"}
    with patch("reports.geoip.urllib.request.urlopen", return_value=_mock_response(payload)):
        assert lookup_ip("203.0.113.5") is None


def test_network_error_returns_none():
    with patch("reports.geoip.urllib.request.urlopen", side_effect=urllib.error.URLError("no network")):
        assert lookup_ip("8.8.8.8") is None


def test_malformed_response_returns_none():
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"not valid json"
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    with patch("reports.geoip.urllib.request.urlopen", return_value=mock_resp):
        assert lookup_ip("8.8.8.8") is None


def test_empty_ip_returns_none_without_network_call():
    with patch("reports.geoip.urllib.request.urlopen") as mock_urlopen:
        assert lookup_ip(None) is None
        assert lookup_ip("") is None
        mock_urlopen.assert_not_called()
