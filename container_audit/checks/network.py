"""Network security checks."""

from __future__ import annotations

import socket
import subprocess
from typing import Any

from container_audit.models import Finding, Severity, Status


class NetworkChecks:
    """Network exposure and connectivity checks."""

    def check_port_exposure(self, host: str, ports: list[int]) -> list[Finding]:
        """Check if ports are exposed on a host."""
        findings = []
        for port in ports:
            is_open = self._check_port(host, port)
            findings.append(Finding(
                check_id=f"NET-PORT-{port}",
                title=f"Port {port} {'open' if is_open else 'closed'} on {host}",
                severity=Severity.MEDIUM if is_open else Severity.INFO,
                status=Status.FAIL if is_open else Status.PASS,
                description=(
                    f"Port {port} is open and accessible on {host}."
                    if is_open else
                    f"Port {port} is not accessible on {host}."
                ),
                remediation="Close unused ports. Use firewalls to restrict access.",
                evidence=f"{host}:{port} - {'OPEN' if is_open else 'CLOSED'}",
            ))
        return findings

    def check_common_services(self, host: str) -> list[Finding]:
        """Check for commonly exposed services."""
        common_ports = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "MSRPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }
        findings = []
        for port, service in common_ports.items():
            is_open = self._check_port(host, port)
            if is_open:
                severity = Severity.HIGH
                if service in ("Telnet", "Redis", "MongoDB", "SMB", "RDP", "VNC"):
                    severity = Severity.CRITICAL
                elif service in ("SSH", "MySQL", "PostgreSQL", "MSSQL", "Elasticsearch"):
                    severity = Severity.HIGH

                findings.append(Finding(
                    check_id=f"NET-SVC-{port}",
                    title=f"{service} ({port}) exposed",
                    severity=severity,
                    status=Status.FAIL,
                    description=f"{service} is exposed on {host}:{port}.",
                    remediation=f"Restrict access to {service} port {port}. Use VPN or allowlisting.",
                    evidence=f"Service: {service}, Port: {port}, Host: {host}",
                ))
        return findings

    def _check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False
