"""Tests for Docker security checks."""

import pytest
from container_audit.checks.docker import DockerChecks
from container_audit.models import Severity, Status


@pytest.fixture
def checks():
    return DockerChecks()


class TestPrivilegedCheck:
    def test_privileged_detected(self, checks, privileged_container):
        finding = checks.check_privileged(privileged_container)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert "privileged" in finding.description.lower()

    def test_not_privileged(self, checks, secure_container):
        finding = checks.check_privileged(secure_container)
        assert finding.status == Status.PASS


class TestDockerSocket:
    def test_socket_detected(self, checks, privileged_container):
        finding = checks.check_docker_socket(privileged_container)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL

    def test_no_socket(self, checks, secure_container):
        finding = checks.check_docker_socket(secure_container)
        assert finding.status == Status.PASS


class TestUserCheck:
    def test_root_user(self, checks, privileged_container):
        finding = checks.check_user(privileged_container)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.MEDIUM

    def test_non_root_user(self, checks, secure_container):
        finding = checks.check_user(secure_container)
        assert finding.status == Status.PASS


class TestCapabilities:
    def test_dangerous_caps(self, checks, privileged_container):
        finding = checks.check_capabilities(privileged_container)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.HIGH

    def test_no_dangerous_caps(self, checks, secure_container):
        finding = checks.check_capabilities(secure_container)
        assert finding.status == Status.PASS


class TestPortExposure:
    def test_exposed_on_all(self, checks, privileged_container):
        finding = checks.check_ports(privileged_container)
        assert finding.status == Status.FAIL

    def test_bound_to_localhost(self, checks, secure_container):
        finding = checks.check_ports(secure_container)
        assert finding.status == Status.PASS


class TestEnvSecrets:
    def test_secrets_detected(self, checks, privileged_container):
        finding = checks.check_env_secrets(privileged_container)
        assert finding.status == Status.FAIL
        assert "MY_APP_TOKEN" in finding.description

    def test_no_secrets(self, checks, secure_container):
        finding = checks.check_env_secrets(secure_container)
        assert finding.status == Status.PASS


class TestReadonlyRootfs:
    def test_writable(self, checks, privileged_container):
        finding = checks.check_readonly_rootfs(privileged_container)
        assert finding.status == Status.FAIL

    def test_readonly(self, checks, secure_container):
        finding = checks.check_readonly_rootfs(secure_container)
        assert finding.status == Status.PASS


class TestResources:
    def test_no_limits(self, checks, privileged_container):
        finding = checks.check_resources(privileged_container)
        assert finding.status == Status.FAIL

    def test_limits_set(self, checks, secure_container):
        finding = checks.check_resources(secure_container)
        assert finding.status == Status.PASS
