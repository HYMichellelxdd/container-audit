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
            "Env": ["PATH=/usr/bin", "DB_PASSWORD=supersecret123"],
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
        "State": {"StfRê