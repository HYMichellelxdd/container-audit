"""Core scanning engine - orchestrates all security checks."""

from __future__ import annotations

import os
import subprocess
import json
from pathlib import Path
from typing import Any

from container_audit.models import Finding, Severity, Status, ScanResult
from container_audit.checks.docker import DockerChecks
from container_audit.checks.kubernetes import KubernetesChecks
from container_audit.checks.network import NetworkChecks
from container_audit.checks.secrets import SecretsChecks


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
