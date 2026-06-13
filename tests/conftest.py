"""Shared test fixtures."""

import pytest


@pytest.fixture
def privileged_container():
    """Mock Docker inspect data for a privileged container."""
    return {
        "Id": "abc123",
        "State": {"Status": "running"},
        "Config": {
            "Image": "ubuntu:22.04",
            "User": "",
            "Env": ["PATH=/usr/bin", "MY_APP_TOKEN=abc123def456ghi789"],
        },
        "HostConfig": {
            "Privileged": True,
            "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
            "PidMode": "",
            "IpcMode": "",
            "NetworkMode": "bridge",
            "ReadonlyRootfs": False,
            "Memory": 0,
            "CpuQuota": 0,
            "PidsLimit": -1,
            "SecurityOpt": [],
            "PortBindings": {
                "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
            }
        ],
    }


@pytest.fixture
def secure_container():
    """Mock Docker inspect data for a well-configured container."""
    return {
        "Id": "def456",
        "State": {"Status": "running"},
        "Config": {
            "Image": "nginx:alpine",
            "User": "1000:1000",
            "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.25"],
            "Healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost/"]},
        },
        "HostConfig": {
            "Privileged": False,
            "CapAdd": [],
            "PidMode": "",
            "IpcMode": "",
            "NetworkMode": "bridge",
            "ReadonlyRootfs": True,
            "Memory": 536870912,
            "CpuQuota": 50000,
            "PidsLimit": 100,
            "SecurityOpt": ["apparmor=docker-default", "seccomp=default"],
            "PortBindings": {
                "443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "443"}],
            },
        },
        "Mounts": [],
    }


@pytest.fixture
def sample_secrets_file(tmp_path):
    """Create a file with detectable patterns for testing."""
    lines = [
        "APP_KEY='sk-test-1234567890abcdefghijklmnop'",
        "DB_CONN='postgres://admin:s3cret123@dbhost:5432/app'",
        "app_pass = 'mypass12345'",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfnygWyF8PbnGy5AH",
    ]
    f = tmp_path / "config.py"
    f.write_text("\n".join(lines))
    return str(f)
