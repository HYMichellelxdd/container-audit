"""Secret and credential detection in files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from container_audit.scanner import Finding, Severity, Status


# Secret detection patterns
SECRET_PATTERNS = [
    # API Keys
    (r"""(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9_\-]{16,})['"]""", "API Key"),
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"""(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9/+=]{40})['"]""", "AWS Secret Key"),
    # GitHub
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "GitHub Token"),
    (r"github_pat_[A-Za-z0-9_]{82,}", "GitHub PAT"),
    # GitLab
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab PAT"),
    # Slack
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack Token"),
    # Private Keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    # Generic passwords
    (r"""(?:password|passwd|pwd)\s*[=:]\s*['"](.{8,})['"]""", "Password"),
    # Connection strings
    (r"(?:mysql|postgres|mongodb|redis|amqp)://[^\s]+", "Connection String"),
    # JWT
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT Token"),
    # GCP
    (r'"type"\s*:\s*"service_account"', "GCP Service Account Key"),
    # Azure
    (r"(?:AccountKey|SharedAccessSignature|DefaultEndpointsProtocol)[=:]\s*[A-Za-z0-9+/=]{20,}", "Azure Credential"),
    # npm
    (r"npm_[A-Za-z0-9]{36}", "npm Token"),
]

# Files to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
}

SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".mp3", ".mp4", ".wav", ".avi",
    ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}


class SecretsChecks:
    """Scan files for leaked secrets and credentials."""

    def scan_path(self, file_path: str) -> list[Finding]:
        """Scan a file or directory for secrets."""
        path = Path(file_path)
        if not path.exists():
            return [Finding(
                check_id="SEC-000",
                title="Path not found",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Path not found: {file_path}",
            )]

        findings = []
        if path.is_file():
            findings.extend(self._scan_file(path))
        elif path.is_dir():
            for f in self._iter_files(path):
                findings.extend(self._scan_file(f))

        return findings

    def _iter_files(self, directory: Path):
        """Iterate through files, skipping irrelevant directories."""
        for item in sorted(directory.rglob("*")):
            if item.is_dir():
                if item.name in SKIP_DIRS:
                    continue
                continue
            if item.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if item.stat().st_size > 1_000_000:  # Skip files > 1MB
                continue
            yield item

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file for secrets."""
        findings = []
        try:
            content = file_path.read_text(errors="ignore")
        except (PermissionError, OSError):
            return findings

        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, secret_type in SECRET_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Redact the actual secret value
                    redacted = line[:match.start()] + "*" * 10 + line[match.end():]
                    findings.append(Finding(
                        check_id=f"SEC-{file_path.name}-{line_num}",
                        title=f"{secret_type} found",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        description=f"{secret_type} detected in {file_path}:{line_num}",
                        remediation="Remove secrets from code. Use environment variables or a secrets manager.",
                        evidence=f"File: {file_path}, Line: {line_num}, Type: {secret_type}",
                        metadata={"file": str(file_path), "line": line_num, "type": secret_type},
                    ))
                    break  # One finding per line

        return findings
