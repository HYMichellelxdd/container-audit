"""Core scanning engine - orchestrates all security checks."""

from __future__ import annotations

import os
import subprocess
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from container_audit.checks.docker import DockerChecks
from container_audit.checks.kubernetes import KubernetesChecks
from container_audit.checks.network import NetworkChecks
from container_audit.checks.secrets import SecretsChecks


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


class Scanner:
    """Main scanner that orchestrates all check modules."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.docker_checks = DockerChecks()
        self.kubernetes_checks = KubernetesChecks()
        self.network_checks = NetworkChecks()
        self.secrets_checks = SecretsChecks()

    def scan_docker(self, target: str) -> ScanResult:
        """Scan a Docker container or image."""
        result = ScanResult(target=target, scan_type="docker")

        # Get container/image info
        info = self._get_docker_info(target)
        if info is None:
            result.findings.append(Finding(
                check_id="DOCKER-000",
                title="Unable to inspect target",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Cannot inspect Docker target: {target}",
                remediation="Ensure Docker is running and the target exists.",
            ))
            return result

        # Run all Docker checks
        checks = [
            self.docker_checks.check_privileged(info),
            self.docker_checks.check_docker_socket(info),
            self.docker_checks.check_user(info),
            self.docker_checks.check_capabilities(info),
            self.docker_checks.check_ports(info),
            self.docker_checks.check_env_secrets(info),
            self.docker_checks.check_readonly_rootfs(info),
            self.docker_checks.check_resources(info),
            self.docker_checks.check_healthcheck(info),
            self.docker_checks.check_apparmor(info),
            self.docker_checks.check_seccomp(info),
            self.docker_checks.check_pid_mode(info),
            self.docker_checks.check_ipc_mode(info),
            self.docker_checks.check_network_mode(info),
        ]
        result.findings.extend(checks)
        return result

    def scan_compose(self, file_path: str) -> ScanResult:
        """Scan a docker-compose file."""
        result = ScanResult(target=file_path, scan_type="compose")
        path = Path(file_path)

        if not path.exists():
            result.findings.append(Finding(
                check_id="COMPOSE-000",
                title="File not found",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Compose file not found: {file_path}",
                remediation="Check the file path and try again.",
            ))
            return result

        try:
            import yaml
            with open(path) as f:
                compose = yaml.safe_load(f)
        except Exception as e:
            result.findings.append(Finding(
                check_id="COMPOSE-001",
                title="Invalid compose file",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Failed to parse compose file: {e}",
                remediation="Ensure the file is valid YAML and follows docker-compose format.",
            ))
            return result

        services = compose.get("services", {})
        for svc_name, svc_config in services.items():
            svc_findings = self.docker_checks.check_compose_service(svc_name, svc_config)
            result.findings.extend(svc_findings)

        return result

    def scan_kubernetes(self, file_path: str) -> ScanResult:
        """Scan a Kubernetes manifest file or directory."""
        result = ScanResult(target=file_path, scan_type="kubernetes")
        path = Path(file_path)

        if not path.exists():
            result.findings.append(Finding(
                check_id="K8S-000",
                title="Path not found",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Kubernetes path not found: {file_path}",
                remediation="Check the file path and try again.",
            ))
            return result

        manifests = self._load_k8s_manifests(path)
        if not manifests:
            result.findings.append(Finding(
                check_id="K8S-001",
                title="No manifests found",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                description="No valid Kubernetes manifests found at the specified path.",
                remediation="Ensure the path contains valid YAML manifests with apiVersion and kind.",
            ))
            return result

        for manifest in manifests:
            kind = manifest.get("kind", "Unknown")
            name = manifest.get("metadata", {}).get("name", "unnamed")
            namespace = manifest.get("metadata", {}).get("namespace", "")

            checks = self.kubernetes_checks.check_manifest(manifest)
            for finding in checks:
                finding.metadata["resource"] = f"{kind}/{name}"
                if namespace:
                    finding.metadata["namespace"] = namespace
            result.findings.extend(checks)

        return result

    def scan_secrets(self, file_path: str) -> ScanResult:
        """Scan a directory or file for leaked secrets."""
        result = ScanResult(target=file_path, scan_type="secrets")
        findings = self.secrets_checks.scan_path(file_path)
        result.findings.extend(findings)
        return result

    def _get_docker_info(self, target: str) -> dict[str, Any] | None:
        """Get Docker container/image inspection info."""
        try:
            result = subprocess.run(
                ["docker", "inspect", target],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data[0] if isinstance(data, list) else data
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _load_k8s_manifests(self, path: Path) -> list[dict[str, Any]]:
        """Load Kubernetes manifests from a file or directory."""
        import yaml

        manifests = []
        files = []

        if path.is_file():
            files = [path]
        elif path.is_dir():
            for ext in ("*.yaml", "*.yml", "*.json"):
                files.extend(path.glob(ext))
                files.extend(path.rglob(ext))
            files = list(set(files))

        for f in sorted(files):
            try:
                with open(f) as fh:
                    docs = list(yaml.safe_load_all(fh.read()))
                    for doc in docs:
                        if doc and isinstance(doc, dict) and "apiVersion" in doc:
                            manifests.append(doc)
            except Exception:
                continue

        return manifests
