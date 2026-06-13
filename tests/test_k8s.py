"""Tests for Kubernetes manifest checks."""

import pytest
import yaml
from container_audit.checks.kubernetes import KubernetesChecks
from container_audit.models import Severity, Status


@pytest.fixture
def checks():
    return KubernetesChecks()


@pytest.fixture
def privileged_deployment():
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "vuln-app", "namespace": "default"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "myapp:latest",
                            "securityContext": {
                                "privileged": True,
                            },
                        }
                    ],
                    "serviceAccountName": "default",
                    "automountServiceAccountToken": True,
                }
            }
        },
    }


@pytest.fixture
def secure_deployment():
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "secure-app", "namespace": "production"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "myapp:latest",
                            "securityContext": {
                                "privileged": False,
                                "runAsNonRoot": True,
                                "runAsUser": 1000,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                    "automountServiceAccountToken": False,
                }
            }
        },
    }


class TestPrivilegedCheck:
    def test_privileged_detected(self, checks, privileged_deployment):
        findings = checks.check_manifest(privileged_deployment)
        priv_findings = [f for f in findings if "privileged" in f.title.lower()]
        assert len(priv_findings) > 0
        assert priv_findings[0].status == Status.FAIL

    def test_not_privileged(self, checks, secure_deployment):
        findings = checks.check_manifest(secure_deployment)
        priv_findings = [f for f in findings if "privileged" in f.title.lower()]
        assert len(priv_findings) > 0
        assert priv_findings[0].status == Status.PASS


class TestNamespaceCheck:
    def test_no_namespace(self):
        checks = KubernetesChecks()
        manifest = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc"},
            "spec": {},
        }
        findings = checks.check_manifest(manifest)
        ns_findings = [f for f in findings if "namespace" in f.title.lower()]
        assert len(ns_findings) > 0
        assert ns_findings[0].status == Status.WARN

    def test_system_namespace(self):
        checks = KubernetesChecks()
        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "kube-system"},
            "spec": {"containers": []},
        }
        findings = checks.check_manifest(manifest)
        sys_findings = [f for f in findings if "system namespace" in f.description.lower()]
        assert len(sys_findings) > 0


class TestServiceAccount:
    def test_token_automounted(self, checks, privileged_deployment):
        findings = checks.check_manifest(privileged_deployment)
        sa_findings = [f for f in findings if "serviceaccount" in f.title.lower() and "token" in f.title.lower()]
        assert len(sa_findings) > 0
        assert sa_findings[0].status == Status.FAIL

    def test_token_not_automounted(self, checks, secure_deployment):
        findings = checks.check_manifest(secure_deployment)
        sa_findings = [f for f in findings if "serviceaccount" in f.title.lower() and "token" in f.title.lower()]
        assert len(sa_findings) > 0
        assert sa_findings[0].status == Status.PASS
