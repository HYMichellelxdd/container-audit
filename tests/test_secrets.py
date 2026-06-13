"""Tests for secret detection."""

import pytest
from container_audit.checks.secrets import SecretsChecks


@pytest.fixture
def checks():
    return SecretsChecks()


class TestSecretDetection:
    def test_detects_api_key(self, checks, sample_secrets_file):
        findings = checks.scan_path(sample_secrets_file)
        api_findings = [f for f in findings if "API Key" in f.title]
        assert len(api_findings) > 0

    def test_detects_password(self, checks, sample_secrets_file):
        findings = checks.scan_path(sample_secrets_file)
        pwd_findings = [f for f in findings if "Credential" in f.title]
        assert len(pwd_findings) > 0

    def test_detects_private_key(self, checks, sample_secrets_file):
        findings = checks.scan_path(sample_secrets_file)
        key_findings = [f for f in findings if "Private Key" in f.title]
        assert len(key_findings) > 0

    def test_detects_connection_string(self, checks, sample_secrets_file):
        findings = checks.scan_path(sample_secrets_file)
        conn_findings = [f for f in findings if "Connection String" in f.title]
        assert len(conn_findings) > 0


class TestSecretScanClean:
    def test_clean_file(self, checks, tmp_path):
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1\nprint(\"hello\")\n")
        findings = checks.scan_path(str(clean_file))
        assert len(findings) == 0


class TestSecretScanNonexistent:
    def test_nonexistent_path(self, checks):
        findings = checks.scan_path("/nonexistent/path")
        assert len(findings) == 1
        assert "not found" in findings[0].description.lower()
