"""Docker security configuration checks."""

from __future__ import annotations

from typing import Any

from container_audit.scanner import Finding, Severity, Status


# Dangerous Linux capabilities
DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE",
    "SYS_BOOT", "AUDIT_WRITE", "MKNOD", "SETFCAP", "MAC_ADMIN",
    "MAC_OVERRIDE", "DAC_READ_SEARCH", "LINUX_IMMUTABLE",
}


class DockerChecks:
    """Security checks for Docker containers and images."""

    def check_privileged(self, info: dict[str, Any]) -> Finding:
        """Check if container runs in privileged mode."""
        privileged = info.get("HostConfig", {}).get("Privileged", False)
        return Finding(
            check_id="DOCKER-001",
            title="Privileged container",
            severity=Severity.CRITICAL,
            status=Status.FAIL if privileged else Status.PASS,
            description=(
                "Container is running in privileged mode, giving it full host access."
                if privileged else
                "Container is not running in privileged mode."
            ),
            remediation="Remove --privileged flag. Use specific capabilities instead.",
            evidence=f"Privileged: {privileged}",
        )

    def check_docker_socket(self, info: dict[str, Any]) -> Finding:
        """Check if Docker socket is mounted."""
        mounts = info.get("Mounts", [])
        socket_mounted = any(
            "/var/run/docker.sock" in str(m.get("Source", "")) or
            "/var/run/docker.sock" in str(m.get("Destination", ""))
            for m in mounts
        )
        return Finding(
            check_id="DOCKER-002",
            title="Docker socket mounted",
            severity=Severity.CRITICAL,
            status=Status.FAIL if socket_mounted else Status.PASS,
            description=(
                "Docker socket is mounted into the container, allowing container escape."
                if socket_mounted else
                "Docker socket is not mounted."
            ),
            remediation="Avoid mounting Docker socket. Use Docker-in-Docker or rootless Docker.",
            evidence=f"Mounts: {[m.get('Destination', '') for m in mounts]}",
        )

    def check_user(self, info: dict[str, Any]) -> Finding:
        """Check if container runs as root."""
        config = info.get("Config", {})
        user = config.get("User", "")
        is_root = user in ("", "root", "0", "0:0")
        return Finding(
            check_id="DOCKER-003",
            title="Running as root",
            severity=Severity.MEDIUM,
            status=Status.FAIL if is_root else Status.PASS,
            description=(
                f"Container runs as root (User: {user or 'not set'})."
                if is_root else
                f"Container runs as non-root user: {user}"
            ),
            remediation="Set USER directive in Dockerfile or --user in docker run.",
            evidence=f"User: {user or '(not set)'}",
        )

    def check_capabilities(self, info: dict[str, Any]) -> Finding:
        """Check for dangerous capabilities."""
        host_config = info.get("HostConfig", {})
        cap_add = host_config.get("CapAdd") or []
        dangerous = [c for c in cap_add if c in DANGEROUS_CAPS]
        return Finding(
            check_id="DOCKER-004",
            title="Dangerous capabilities added",
            severity=Severity.HIGH,
            status=Status.FAIL if dangerous else Status.PASS,
            description=(
                f"Dangerous capabilities detected: {', '.join(dangerous)}"
                if dangerous else
                "No dangerous capabilities detected."
            ),
            remediation="Remove unnecessary capabilities. Use --cap-drop ALL --cap-add <specific>.",
            evidence=f"CapAdd: {cap_add}",
        )

    def check_ports(self, info: dict[str, Any]) -> Finding:
        """Check for exposed ports on all interfaces."""
        host_config = info.get("HostConfig", {})
        port_bindings = host_config.get("PortBindings") or {}
        exposed_all = []
        for port, bindings in port_bindings.items():
            if bindings:
                for binding in bindings:
                    host_ip = binding.get("HostIp", "")
                    if host_ip in ("", "0.0.0.0"):
                        exposed_all.append(port)

        return Finding(
            check_id="DOCKER-005",
            title="Ports exposed on all interfaces",
            severity=Severity.MEDIUM,
            status=Status.FAIL if exposed_all else Status.PASS,
            description=(
                f"Ports exposed on 0.0.0.0: {', '.join(exposed_all)}"
                if exposed_all else
                "No ports exposed on all interfaces."
            ),
            remediation="Bind to specific IP: -p 127.0.0.1:8080:8080",
            evidence=f"PortBindings: {port_bindings}",
        )

    def check_env_secrets(self, info: dict[str, Any]) -> Finding:
        """Check for secrets in environment variables."""
        config = info.get("Config", {})
        env_vars = config.get("Env") or []
        secret_patterns = [
            "PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY",
            "AWS_ACCESS", "AWS_SECRET", "DATABASE_URL", "STRIPE",
        ]
        found_secrets = []
        for env in env_vars:
            key = env.split("=", 1)[0] if "=" in env else ""
            if any(pattern in key.upper() for pattern in secret_patterns):
                found_secrets.append(key)

        return Finding(
            check_id="DOCKER-006",
            title="Secrets in environment variables",
            severity=Severity.HIGH,
            status=Status.FAIL if found_secrets else Status.PASS,
            description=(
                f"Potential secrets found in env vars: {', '.join(found_secrets)}"
                if found_secrets else
                "No secrets detected in environment variables."
            ),
            remediation="Use Docker secrets, mounted files, or a secrets manager instead.",
            evidence=f"Env keys: {[e.split('=')[0] for e in env_vars]}",
        )

    def check_readonly_rootfs(self, info: dict[str, Any]) -> Finding:
        """Check if root filesystem is read-only."""
        host_config = info.get("HostConfig", {})
        readonly = host_config.get("ReadonlyRootfs", False)
        return Finding(
            check_id="DOCKER-007",
            title="Writable root filesystem",
            severity=Severity.LOW,
            status=Status.FAIL if not readonly else Status.PASS,
            description=(
                "Root filesystem is writable."
                if not readonly else
                "Root filesystem is read-only."
            ),
            remediation="Use --read-only flag. Mount tmpfs for writable paths.",
            evidence=f"ReadonlyRootfs: {readonly}",
        )

    def check_resources(self, info: dict[str, Any]) -> Finding:
        """Check if resource limits are set."""
        host_config = info.get("HostConfig", {})
        memory = host_config.get("Memory", 0)
        cpu_quota = host_config.get("CpuQuota", 0)
        pids_limit = host_config.get("PidsLimit", -1)

        missing = []
        if memory == 0:
            missing.append("memory")
        if cpu_quota == 0:
            missing.append("CPU")
        if pids_limit in (0, -1, None):
            missing.append("PIDs")

        return Finding(
            check_id="DOCKER-008",
            title="Resource limits not set",
            severity=Severity.MEDIUM,
            status=Status.FAIL if missing else Status.PASS,
            description=(
                f"Missing resource limits: {', '.join(missing)}"
                if missing else
                "Resource limits are configured."
            ),
            remediation="Set --memory, --cpus, and --pids-limit flags.",
            evidence=f"Memory: {memory}, CpuQuota: {cpu_quota}, PidsLimit: {pids_limit}",
        )

    def check_healthcheck(self, info: dict[str, Any]) -> Finding:
        """Check if healthcheck is configured."""
        config = info.get("Config", {})
        healthcheck = config.get("Healthcheck")
        has_check = bool(healthcheck and healthcheck.get("Test"))
        return Finding(
            check_id="DOCKER-009",
            title="No healthcheck configured",
            severity=Severity.LOW,
            status=Status.FAIL if not has_check else Status.PASS,
            description=(
                "No healthcheck configured."
                if not has_check else
                "Healthcheck is configured."
            ),
            remediation="Add HEALTHCHECK instruction in Dockerfile or --health-cmd in docker run.",
            evidence=f"Healthcheck: {healthcheck}",
        )

    def check_apparmor(self, info: dict[str, Any]) -> Finding:
        """Check AppArmor profile."""
        host_config = info.get("HostConfig", {})
        apparmor = host_config.get("SecurityOpt") or []
        has_profile = any("apparmor" in str(opt).lower() for opt in apparmor)
        return Finding(
            check_id="DOCKER-010",
            title="AppArmor profile",
            severity=Severity.LOW,
            status=Status.PASS if has_profile else Status.WARN,
            description=(
                f"AppArmor profile applied: {apparmor}"
                if has_profile else
                "No custom AppArmor profile set (using default)."
            ),
            remediation="Consider using a custom AppArmor profile for production.",
            evidence=f"SecurityOpt: {apparmor}",
        )

    def check_seccomp(self, info: dict[str, Any]) -> Finding:
        """Check Seccomp profile."""
        host_config = info.get("HostConfig", {})
        security_opt = host_config.get("SecurityOpt") or []
        has_seccomp = any("seccomp" in str(opt).lower() for opt in security_opt)
        return Finding(
            check_id="DOCKER-011",
            title="Seccomp profile",
            severity=Severity.LOW,
            status=Status.PASS if has_seccomp else Status.WARN,
            description=(
                f"Seccomp profile configured."
                if has_seccomp else
                "No custom Seccomp profile (using default)."
            ),
            remediation="Consider using a custom Seccomp profile.",
            evidence=f"SecurityOpt: {security_opt}",
        )

    def check_pid_mode(self, info: dict[str, Any]) -> Finding:
        """Check if host PID namespace is shared."""
        host_config = info.get("HostConfig", {})
        pid_mode = host_config.get("PidMode", "")
        is_host = pid_mode == "host"
        return Finding(
            check_id="DOCKER-012",
            title="Host PID namespace",
            severity=Severity.HIGH,
            status=Status.FAIL if is_host else Status.PASS,
            description=(
                "Container shares host PID namespace."
                if is_host else
                "Container uses its own PID namespace."
            ),
            remediation="Remove --pid=host flag.",
            evidence=f"PidMode: {pid_mode}",
        )

    def check_ipc_mode(self, info: dict[str, Any]) -> Finding:
        """Check if host IPC namespace is shared."""
        host_config = info.get("HostConfig", {})
        ipc_mode = host_config.get("IpcMode", "")
        is_host = ipc_mode == "host"
        return Finding(
            check_id="DOCKER-013",
            title="Host IPC namespace",
            severity=Severity.MEDIUM,
            status=Status.FAIL if is_host else Status.PASS,
            description=(
                "Container shares host IPC namespace."
                if is_host else
                "Container uses its own IPC namespace."
            ),
            remediation="Remove --ipc=host flag.",
            evidence=f"IpcMode: {ipc_mode}",
        )

    def check_network_mode(self, info: dict[str, Any]) -> Finding:
        """Check if host network mode is used."""
        host_config = info.get("HostConfig", {})
        network_mode = host_config.get("NetworkMode", "")
        is_host = network_mode == "host"
        return Finding(
            check_id="DOCKER-014",
            title="Host network mode",
            severity=Severity.HIGH,
            status=Status.FAIL if is_host else Status.PASS,
            description=(
                "Container uses host network mode."
                if is_host else
                f"Container uses network mode: {network_mode}"
            ),
            remediation="Use bridge or overlay network instead of host mode.",
            evidence=f"NetworkMode: {network_mode}",
        )

    def check_compose_service(self, name: str, config: dict[str, Any]) -> list[Finding]:
        """Check a docker-compose service definition."""
        findings = []

        # Privileged
        privileged = config.get("privileged", False)
        findings.append(Finding(
            check_id=f"COMPOSE-{name}-001",
            title=f"Service '{name}': privileged mode",
            severity=Severity.CRITICAL,
            status=Status.FAIL if privileged else Status.PASS,
            description=f"Service '{name}' runs in privileged mode." if privileged else f"Service '{name}' is not privileged.",
            remediation="Remove 'privileged: true'.",
        ))

        # Docker socket
        volumes = config.get("volumes", [])
        socket_mounted = any("/var/run/docker.sock" in str(v) for v in volumes)
        findings.append(Finding(
            check_id=f"COMPOSE-{name}-002",
            title=f"Service '{name}': Docker socket mounted",
            severity=Severity.CRITICAL,
            status=Status.FAIL if socket_mounted else Status.PASS,
            description=f"Docker socket mounted in '{name}'." if socket_mounted else f"No Docker socket in '{name}'.",
            remediation="Remove Docker socket volume mount.",
        ))

        # Root user
        user = config.get("user", "")
        is_root = user in ("", "root", "0", "0:0")
        findings.append(Finding(
            check_id=f"COMPOSE-{name}-003",
            title=f"Service '{name}': running as root",
            severity=Severity.MEDIUM,
            status=Status.FAIL if is_root else Status.PASS,
            description=f"Service '{name}' runs as root." if is_root else f"Service '{name}' runs as user: {user}",
            remediation="Add user: '1000:1000' or similar.",
        ))

        # Capabilities
        cap_add = config.get("cap_add", [])
        dangerous = [c for c in cap_add if c in DANGEROUS_CAPS]
        findings.append(Finding(
            check_id=f"COMPOSE-{name}-004",
            title=f"Service '{name}': dangerous capabilities",
            severity=Severity.HIGH,
            status=Status.FAIL if dangerous else Status.PASS,
            description=f"Dangerous capabilities in '{name}': {', '.join(dangerous)}" if dangerous else f"No dangerous caps in '{name}'.",
            remediation="Remove unnecessary capabilities.",
        ))

        # Network mode
        network_mode = config.get("network_mode", "")
        if network_mode == "host":
            findings.append(Finding(
                check_id=f"COMPOSE-{name}-005",
                title=f"Service '{name}': host network mode",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Service '{name}' uses host network mode.",
                remediation="Use named network instead.",
            ))

        return findings
