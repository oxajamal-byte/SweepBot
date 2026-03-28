import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sweepbot.utils import save_report, print_summary


MOCK_REPORT = {
    "ip": "185.220.101.34",
    "generated_at": "2024-01-01T00:00:00+00:00",
    "virustotal": {
        "malicious_votes": 42,
        "suspicious_votes": 3,
        "harmless_votes": 10,
        "undetected_votes": 5,
        "reputation_score": -75,
        "country": "DE",
        "asn": 4444,
        "as_owner": "Tor Network",
        "network": "185.220.101.0/24",
    },
    "abuseipdb": {
        "abuse_confidence_score": 100,
        "total_reports": 512,
        "num_distinct_users": 88,
        "last_reported_at": "2024-01-01T00:00:00+00:00",
        "is_whitelisted": False,
        "usage_type": "Tor Exit Node",
        "isp": "Tor Project",
        "domain": "torproject.org",
        "country_code": "DE",
    },
    "shodan": {
        "org": "Tor Network",
        "isp": "Tor Network",
        "country_code": "DE",
        "city": "Frankfurt",
        "os": None,
        "open_ports": [9001, 9030],
        "services": [
            {"port": 9001, "transport": "tcp", "product": "Tor", "version": None, "cpe": []},
        ],
        "tags": ["tor"],
        "vulns": ["CVE-2022-1234"],
        "last_update": "2024-01-01T00:00:00",
    },
}

MOCK_REPORT_WITH_ERRORS = {
    "ip": "1.2.3.4",
    "generated_at": "2024-01-01T00:00:00+00:00",
    "virustotal": {"error": "VIRUSTOTAL_API_KEY not set"},
    "abuseipdb": {"error": "ABUSEIPDB_API_KEY not set"},
    "shodan": {"error": "No information available for this IP"},
}


class TestSaveReport:
    def test_saves_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sweepbot.utils.REPORTS_DIR", Path(tmpdir)):
                path = save_report(MOCK_REPORT)
                assert os.path.exists(path)
                with open(path) as f:
                    loaded = json.load(f)
                assert loaded["ip"] == MOCK_REPORT["ip"]

    def test_filename_contains_ip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sweepbot.utils.REPORTS_DIR", Path(tmpdir)):
                path = save_report(MOCK_REPORT)
                assert "185_220_101_34" in Path(path).name

    def test_filename_has_json_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sweepbot.utils.REPORTS_DIR", Path(tmpdir)):
                path = save_report(MOCK_REPORT)
                assert path.endswith(".json")

    def test_creates_reports_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "nested" / "reports"
            with patch("sweepbot.utils.REPORTS_DIR", new_dir):
                save_report(MOCK_REPORT)
                assert new_dir.exists()


class TestPrintSummary:
    def test_prints_ip_header(self, capsys):
        print_summary(MOCK_REPORT)
        captured = capsys.readouterr()
        assert "185.220.101.34" in captured.out

    def test_flags_malicious_votes(self, capsys):
        print_summary(MOCK_REPORT)
        captured = capsys.readouterr()
        assert "FLAGGED" in captured.out

    def test_flags_high_abuse_score(self, capsys):
        print_summary(MOCK_REPORT)
        captured = capsys.readouterr()
        assert "HIGH RISK" in captured.out

    def test_flags_cves(self, capsys):
        print_summary(MOCK_REPORT)
        captured = capsys.readouterr()
        assert "CVE-2022-1234" in captured.out
        assert "VULNERABILITIES DETECTED" in captured.out

    def test_handles_api_errors_gracefully(self, capsys):
        print_summary(MOCK_REPORT_WITH_ERRORS)
        captured = capsys.readouterr()
        assert "!" in captured.out
        assert "1.2.3.4" in captured.out

    def test_verdict_high_risk(self, capsys):
        print_summary(MOCK_REPORT)
        captured = capsys.readouterr()
        assert "VERDICT" in captured.out
        assert "HIGH RISK" in captured.out

    def test_verdict_unknown_when_all_errors(self, capsys):
        print_summary(MOCK_REPORT_WITH_ERRORS)
        captured = capsys.readouterr()
        assert "VERDICT" in captured.out
        assert "UNKNOWN" in captured.out

    def test_clean_output_no_exceptions(self):
        print_summary(MOCK_REPORT)
        print_summary(MOCK_REPORT_WITH_ERRORS)
