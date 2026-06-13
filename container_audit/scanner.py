"""Core scanning engine."""

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


class Scanner:
    """Main scanner that orchestrates all check modules."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.docker_checks = DockerChecks()
        self.kubernetes_checks = KubernetesChecks()
        self.network_checks = NetworkChecks()

    def scan_docker(self, target: str) -> ScanResult:
        result = ScanResult(target=target, scan_type="docker")
        info = self._get_docker_info(target)
        if info is None:
            result.findings.append(Finding(
                check_id="DOCKER-000", title="Unable to inspect target",
                severity=Severity.HIGH, status=Status.FAIL,
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
            self.docker_checks.check_docker_socket_permissions(info),
        ]
        result.findings.extend(checks)
        return result

    def scan_compose(self, file_path: str) -> ScanResult:
        result = ScanResult(target=file_path, scan_type="compose")
        path = Path(file_path)
        if not path.exists():
            result.findings.append(Finding(
                check_id="COMPOSE-000", title="File not found",
                severity=Severity.HIGH, status=Status.FAIL,
                description=f"Compose file not found: {file_path}",
            ))
            return result
        try:
            import yaml
            with open(path) as f:
                compose = yaml.safe_load(f)
        except Exception as e:
            result.findings.append(Finding(
                check_id="COMPOSE-001", title="Invalid compose file",
                severity=Severity.HIGH, status=Status.FAIL,
                description=f"Failed to parse: {e}",
            ))
            return result
        for svc_name, svc_config in compose.get("services", {}).items():
            result.findings.extend(self.docker_checks.check_compose_service(svc_name, svc_config))
        return result

    def scan_kubernetes(self, file_path: str) -> ScanResult:
        result = ScanResult(target=file_path, scan_type="kubernetes")
        path = Path(file_path)
        if not path.exists():
            result.findings.append(Finding(
                check_id="K8S-000", title="Path not found",
                severity=Severity.HIGH, status=Status.FAIL,
                description=f"Path not found: {file_path}",
            ))
            return result
        manifests = self._load_k8s_manifests(path)
        if not manifests:
            result.findings.append(Finding(
                check_id="K8S-001", title="No manifests found",
                severity=Severity.MEDIUM, status=Status.WARN,
                description="No valid Kubernetes manifests found.",
            ))
            return result
        for manifest in manifests:
            kind = manifest.get("kind", "Unknown")
            name = manifest.get("metadata", {}).get("name", "unnamed")
            ns = manifest.get("metadata", {}).get("namespace", "")
            for f in self.kubernetes_checks.check_manifest(manifest):
                f.metadata["resource"] = f"{kind}/{name}"
                if ns:
                    f.metadata["namespace"] = ns
                result.findings.append(f)
        return result

    def _get_docker_info(self, target: str) -> dict[str, Any] | None:
        try:
            r = subprocess.run(["docker", "inspect", target], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                data = json.loads(r.stdout)
                return data[0] if isinstance(data, list) else data
        except Exception:
            pass
        return None

    def _load_k8s_manifests(self, path: Path) -> list[dict[str, Any]]:
        import yaml
        manifests = []
        files = [path] if path.is_file() else list(set(
            list(path.glob("*.yaml")) + list(path.glob("*.yml")) + list(path.glob("*.json")) +
            list(path.rglob("*.yaml")) + list(path.rglob("*.yml")) + list(path.rglob("*.json"))
        ))
        for f in sorted(files):
            try:
                with open(f) as fh:
                    for doc in yaml.safe_load_all(fh.read()) or []:
                        if doc and isinstance(doc, dict) and "apiVersion" in doc:
                            manifests.append(doc)
            except Exception:
                continue
        return manifests
