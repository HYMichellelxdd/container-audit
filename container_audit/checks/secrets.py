"""Secret and credential detection in files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from container_audit.models import Finding, Severity, Status


# Detection patterns - each is (regex, label)
PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Cloud Access Key"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "SCM Token"),
    (r"github_pat_[A-Za-z0-9_]{82,}", "SCM PAT"),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "SCM PAT"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Chat Token"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "Signed Token"),
    (r"(?:mysql|postgres|mongodb|redis|amqp)://[^\\s]+", "Connection String"),
    (r"npm_[A-Za-z0-9]{36}", "Package Token"),
]

# Additional key-value patterns
KV_PATTERNS = [
    (r"(?:api[_-]?key|apikey)\s*[=:]\s*[\'\"\x60]([A-Za-z0-9_\-]{16,})[\'\"\x60]", "API Key"),
    (r"(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*[\'\"\x60]([A-Za-z0-9/+=]{40})[\'\"\x60]", "Cloud Secret"),
    (r"(?:password|passwd|pwd)\s*[=:]\s*[\'\"\x60]([\x21-\x7E]{8,})[\'\"\x60]", "Cleartext Credential"),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_EXT = {".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".jpg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".pdf"}


class SecretsChecks:
    """Scan files for leaked credentials and sensitive patterns."""

    def scan_path(self, file_path: str) -> list[Finding]:
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
        for item in sorted(directory.rglob("*")):
            if item.is_dir():
                if item.name in SKIP_DIRS:
                    continue
                continue
            if item.suffix.lower() in SKIP_EXT:
                continue
            if item.stat().st_size > 1_000_000:
                continue
            yield item

    def _scan_file(self, file_path: Path) -> list[Finding]:
        findings = []
        try:
            content = file_path.read_text(errors="ignore")
        except (PermissionError, OSError):
            return findings

        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, label in PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        check_id=f"SEC-{file_path.name}-{line_num}",
                        title=f"{label} detected",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        description=f"{label} found in {file_path}:{line_num}",
                        remediation="Move to environment variables or a vault service.",
                        evidence=f"File: {file_path}, Line: {line_num}",
                    ))
                    break

            for pattern, label in KV_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        check_id=f"SEC-KV-{file_path.name}-{line_num}",
                        title=f"{label} detected",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        description=f"{label} found in {file_path}:{line_num}",
                        remediation="Move to environment variables or a vault service.",
                        evidence=f"File: {file_path}, Line: {line_num}",
                    ))
                    break

        return findings
