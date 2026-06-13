"""Kubernetes manifest security checks."""

from __future__ import annotations

from typing import Any

from container_audit.models import Finding, Severity, Status


class KubernetesChecks:
    """Security checks for Kubernetes manifests."""

    def check_manifest(self, manifest: dict[str, Any]) -> list[Finding]:
        """Run all applicable checks on a manifest."""
        kind = manifest.get("kind", "")
        findings = []

        # Common checks for all resource types
        findings.append(self._check_namespace(manifest))

        # Pod/Deployment/StatefulSet/DaemonSet specific
        pod_spec = self._extract_pod_spec(manifest)
        if pod_spec:
            findings.extend(self._check_pod_spec(pod_spec, kind))

        # RBAC checks
        if kind in ("ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"):
            findings.append(self._check_rbac(manifest))

        # ServiceAccount checks
        if kind == "ServiceAccount":
            findings.append(self._check_service_account(manifest))

        # NetworkPolicy check
        if kind == "NetworkPolicy":
            findings.append(self._check_network_policy(manifest))

        # Ingress checks
        if kind == "Ingress":
            findings.extend(self._check_ingress(manifest))

        return [f for f in findings if f is not None]

    def _extract_pod_spec(self, manifest: dict[str, Any]) -> dict[str, Any] | None:
        """Extract PodSpec from various resource types."""
        kind = manifest.get("kind", "")
        spec = manifest.get("spec", {})

        if kind == "Pod":
            return spec
        elif kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"):
            template = spec.get("template", {})
            return template.get("spec", {})
        elif kind == "Job" or kind == "CronJob":
            if kind == "CronJob":
                job_spec = spec.get("jobTemplate", {}).get("spec", {})
                return job_spec.get("template", {}).get("spec", {})
            return spec.get("template", {}).get("spec", {})
        return None

    def _check_namespace(self, manifest: dict[str, Any]) -> Finding:
        """Check if namespace is set."""
        namespace = manifest.get("metadata", {}).get("namespace", "")
        kind = manifest.get("kind", "")
        name = manifest.get("metadata", {}).get("name", "unnamed")

        if kind in ("Namespace", "ClusterRole", "ClusterRoleBinding", "PersistentVolume", "CustomResourceDefinition"):
            return Finding(
                check_id="K8S-NS-001",
                title="Cluster-scoped resource",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                description=f"{kind}/{name} is cluster-scoped (no namespace isolation).",
                remediation="Consider using namespace-scoped resources when possible.",
            )

        if not namespace:
            return Finding(
                check_id="K8S-NS-002",
                title="No namespace specified",
                severity=Severity.LOW,
                status=Status.WARN,
                description=f"{kind}/{name} has no namespace set. Will use 'default'.",
                remediation="Explicitly set metadata.namespace for clarity.",
            )

        if namespace in ("kube-system", "kube-public", "kube-node-lease"):
            return Finding(
                check_id="K8S-NS-003",
                title=f"Resource in system namespace: {namespace}",
                severity=Severity.HIGH,
                status=Status.WARN,
                description=f"{kind}/{name} is in system namespace '{namespace}'.",
                remediation="Avoid deploying to system namespaces unless necessary.",
            )

        return Finding(
            check_id="K8S-NS-000",
            title="Namespace configured",
            severity=Severity.INFO,
            status=Status.PASS,
            description=f"{kind}/{name} is in namespace: {namespace}",
        )

    def _check_pod_spec(self, spec: dict[str, Any], kind: str) -> list[Finding]:
        """Check PodSpec security settings."""
        findings = []

        # Privileged containers
        for c in self._all_containers(spec):
            name = c.get("name", "unnamed")
            security = c.get("securityContext", {})
            privileged = security.get("privileged", False)
            findings.append(Finding(
                check_id=f"K8S-PRIV-{name}",
                title=f"Container '{name}': privileged mode",
                severity=Severity.CRITICAL,
                status=Status.FAIL if privileged else Status.PASS,
                description=f"Container '{name}' runs in privileged mode." if privileged else f"Container '{name}' is not privileged.",
                remediation="Set securityContext.privileged: false",
            ))

            # Root user
            run_as_user = security.get("runAsUser")
            run_as_non_root = security.get("runAsNonRoot", False)
            is_root = run_as_user in (0, None) and not run_as_non_root
            findings.append(Finding(
                check_id=f"K8S-ROOT-{name}",
                title=f"Container '{name}': may run as root",
                severity=Severity.MEDIUM,
                status=Status.FAIL if is_root else Status.PASS,
                description=(
                    f"Container '{name}' may run as root (runAsUser: {run_as_user}, runAsNonRoot: {run_as_non_root})."
                    if is_root else
                    f"Container '{name}' runs as non-root."
                ),
                remediation="Set runAsNonRoot: true and runAsUser: 1000.",
            ))

            # Read-only rootfs
            readonly_fs = security.get("readOnlyRootFilesystem", False)
            findings.append(Finding(
                check_id=f"K8S-ROFS-{name}",
                title=f"Container '{name}': writable root filesystem",
                severity=Severity.LOW,
                status=Status.FAIL if not readonly_fs else Status.PASS,
                description=(
                    f"Container '{name}' has writable root filesystem."
                    if not readonly_fs else
                    f"Container '{name}' has read-only root filesystem."
                ),
                remediation="Set securityContext.readOnlyRootFilesystem: true.",
            ))

            # Capabilities
            caps = security.get("capabilities", {})
            cap_add = caps.get("add", [])
            dangerous = [c for c in cap_add if c in ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL")]
            findings.append(Finding(
                check_id=f"K8S-CAPS-{name}",
                title=f"Container '{name}': dangerous capabilities",
                severity=Severity.HIGH,
                status=Status.FAIL if dangerous else Status.PASS,
                description=(
                    f"Container '{name}' has dangerous capabilities: {', '.join(dangerous)}"
                    if dangerous else
                    f"Container '{name}' has no dangerous capabilities added."
                ),
                remediation="Remove dangerous capabilities. Use drop: [ALL] then add only what's needed.",
            ))

        # ServiceAccount token automounting
        sa_name = spec.get("serviceAccountName", "default")
        automount = spec.get("automountServiceAccountToken", True)
        findings.append(Finding(
            check_id="K8S-SA-TOKEN",
            title="ServiceAccount token auto-mounted",
            severity=Severity.MEDIUM,
            status=Status.FAIL if automount else Status.PASS,
            description=(
                f"ServiceAccount token is auto-mounted into pods (SA: {sa_name})."
                if automount else
                "ServiceAccount token auto-mounting is disabled."
            ),
            remediation="Set automountServiceAccountToken: false if API access is not needed.",
        ))

        # HostNetwork / HostPID / HostIPC
        host_network = spec.get("hostNetwork", False)
        host_pid = spec.get("hostPID", False)
        host_ipc = spec.get("hostIPC", False)

        if host_network:
            findings.append(Finding(
                check_id="K8S-HNET",
                title="Host network enabled",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="Pod uses host network namespace.",
                remediation="Remove hostNetwork: true.",
            ))
        if host_pid:
            findings.append(Finding(
                check_id="K8S-HPID",
                title="Host PID namespace",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="Pod shares host PID namespace.",
                remediation="Remove hostPID: true.",
            ))
        if host_ipc:
            findings.append(Finding(
                check_id="K8S-HIPC",
                title="Host IPC namespace",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="Pod shares host IPC namespace.",
                remediation="Remove hostIPC: true.",
            ))

        # HostPath volumes
        volumes = spec.get("volumes", [])
        host_path_vols = [v for v in volumes if "hostPath" in v]
        if host_path_vols:
            paths = [v["hostPath"].get("path", "") for v in host_path_vols]
            findings.append(Finding(
                check_id="K8S-HOSTPATH",
                title="HostPath volumes mounted",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"HostPath volumes detected: {', '.join(paths)}",
                remediation="Use PersistentVolumes or emptyDir instead of HostPath.",
            ))

        return findings

    def _all_containers(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        """Get all containers (init + regular)."""
        containers = list(spec.get("containers", []))
        containers.extend(spec.get("initContainers", []))
        containers.extend(spec.get("ephemeralContainers", []))
        return containers

    def _check_rbac(self, manifest: dict[str, Any]) -> Finding:
        """Check RBAC permissions."""
        kind = manifest.get("kind", "")
        name = manifest.get("metadata", {}).get("name", "unnamed")
        rules = manifest.get("rules", [])

        # Check for wildcard permissions
        has_wildcard_resources = any(
            "*" in (rule.get("resources") or []) for rule in rules
        )
        has_wildcard_verbs = any(
            "*" in (rule.get("verbs") or []) for rule in rules
        )
        has_wildcard_api = any(
            "*" in (rule.get("apiGroups") or []) for rule in rules
        )

        is_overprivileged = has_wildcard_resources and has_wildcard_verbs

        return Finding(
            check_id=f"K8S-RBAC-{name}",
            title=f"{kind}/{name}: overprivileged RBAC",
            severity=Severity.HIGH if is_overprivileged else Severity.LOW,
            status=Status.FAIL if is_overprivileged else Status.PASS,
            description=(
                f"{kind}/{name} has wildcard permissions (resources: *, verbs: *)."
                if is_overprivileged else
                f"{kind}/{name} has specific RBAC rules."
            ),
            remediation="Follow principle of least privilege. Restrict resources and verbs.",
            evidence=f"Rules count: {len(rules)}, Wildcards: resources={has_wildcard_resources}, verbs={has_wildcard_verbs}",
        )

    def _check_service_account(self, manifest: dict[str, Any]) -> Finding:
        """Check ServiceAccount configuration."""
        name = manifest.get("metadata", {}).get("name", "unnamed")
        secrets = manifest.get("secrets", [])

        return Finding(
            check_id=f"K8S-SA-{name}",
            title=f"ServiceAccount '{name}' secrets",
            severity=Severity.LOW,
            status=Status.WARN if secrets else Status.INFO,
            description=(
                f"ServiceAccount '{name}' has {len(secrets)} pre-created secrets."
                if secrets else
                f"ServiceAccount '{name}' has no pre-created secrets."
            ),
            remediation="Avoid pre-creating secrets for ServiceAccounts.",
        )

    def _check_network_policy(self, manifest: dict[str, Any]) -> Finding:
        """Check NetworkPolicy."""
        name = manifest.get("metadata", {}).get("name", "unnamed")
        spec = manifest.get("spec", {})
        pod_selector = spec.get("podSelector", {})
        policy_types = spec.get("policyTypes", [])

        has_egress = "Egress" in policy_types
        has_ingress = "Ingress" in policy_types

        if not has_egress and not has_ingress:
            return Finding(
                check_id=f"K8S-NP-{name}",
                title=f"NetworkPolicy '{name}': no policy types",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                description=f"NetworkPolicy '{name}' has no policyTypes defined.",
                remediation="Specify policyTypes: [Ingress, Egress].",
            )

        return Finding(
            check_id=f"K8S-NP-{name}",
            title=f"NetworkPolicy '{name}': configured",
            severity=Severity.INFO,
            status=Status.PASS,
            description=f"NetworkPolicy '{name}' covers: {', '.join(policy_types)}",
        )

    def _check_ingress(self, manifest: dict[str, Any]) -> list[Finding]:
        """Check Ingress security."""
        findings = []
        name = manifest.get("metadata", {}).get("name", "unnamed")
        spec = manifest.get("spec", {})
        tls = spec.get("tls", [])

        if not tls:
            findings.append(Finding(
                check_id=f"K8S-ING-TLS-{name}",
                title=f"Ingress '{name}': no TLS",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Ingress '{name}' has no TLS configuration.",
                remediation="Configure TLS with valid certificates.",
            ))

        annotations = manifest.get("metadata", {}).get("annotations", {})
        ssl_redirect = annotations.get("nginx.ingress.kubernetes.io/ssl-redirect", "true")
        if ssl_redirect == "false":
            findings.append(Finding(
                check_id=f"K8S-ING-REDIR-{name}",
                title=f"Ingress '{name}': SSL redirect disabled",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="SSL redirect is disabled.",
                remediation="Enable ssl-redirect annotation.",
            ))

        return findings
