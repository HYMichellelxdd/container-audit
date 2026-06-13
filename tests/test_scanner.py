"""Tests for the scanner engine."""

import pytest
from container_audit.models import Finding, ScanResult, Severity, Status


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult(target="test", scan_type="docker")
        assert result.score == 100
        assert result.total_passed == 0
        assert result.total_failed == 0

    def test_score_calculation(self):
        result = ScanResult(target="test", scan_type="docker")
        result.findings = [
            Finding("1", "Critical Issue", Severity.CRITICAL, Status.FAIL, "desc"),
            Finding("2", "High Issue", Severity.HIGH, Status.FAIL, "desc"),
            Finding("3", "Pass Check", Severity.HIGH, Status.PASS, "desc"),
        ]
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.total_passed == 1
        assert result.score < 100

    def test_to_dict(self):
        result = ScanResult(target="test", scan_type="docker")
        result.findings = [
            Finding("1", "Check", Severity.LOW, Status.PASS, "OK"),
        ]
        d = result.to_dict()
        assert d["target"] == "test"
        assert d["scan_type"] == "docker"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "low"
