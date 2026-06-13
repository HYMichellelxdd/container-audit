"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class Finding:
    """A single security finding."""

    check_id: str
    title: str
    severity: Severity
    status: Status
    description: str
    remediation: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """Aggregated scan results."""

    target: str
    scan_type: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL and f.status == Status.FAIL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and f.status == Status.FAIL)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM and f.status == Status.FAIL)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW and f.status == Status.FAIL)

    @property
    def total_passed(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.PASS)

    @property
    def total_failed(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL)

    @property
    def total_warnings(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.WARN)

    @property
    def score(self) -> int:
        """Security score 0-100."""
        if not self.findings:
            return 100
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        max_penalty = sum(weights[f.severity] for f in self.findings)
        actual_penalty = sum(
            weights[f.severity] for f in self.findings if f.status in (Status.FAIL, Status.WARN)
        )
        if max_penalty == 0:
            return 100
        return max(0, round(100 - (actual_penalty / max_penalty) * 100))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "score": self.score,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "passed": self.total_passed,
                "failed": self.total_failed,
                "warnings": self.total_warnings,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
