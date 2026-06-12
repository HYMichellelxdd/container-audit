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
            "Memory": 536870912,  # 512MB
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
def sample_compose():
    """Sample docker-compose content."""
    return """
version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    privileged: true
    cap_add:
      - SYS_ADMIN

  api:
    image: node:18-alpine
    user: "1000:1000"
    cap_drop:
      - ALL
    read_only: true
"""


@pytest.fixture
def sample_k8s_manifest():
    """Sample Kubernetes manifest."""
    return """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable
  template:
    metadata:
      labels:
        app: vulnerable
    spec:
      containers:
        - name: app
          image: myapp:latest
          securityContext:
            privileged: true
          volumeMounts:
            - name: host-root
              mountPath: /host
      volumes:
        - name: host-root
          hostPath:
            path: /
      serviceAccountName: default
"""


@pytest.fixture
def sample_secrets_file(tmp_path):
    """Create a file with secrets for testing."""
    content = """
# Config file
API_KEY=sk-1234567890abcdef1234567890abcdef
DATABASE_URL=postgres://user:password@localhost:5432/db
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
password = "hunter2"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AH...
"""
    secrets_file = tmp_path / "config.py"
    secrets_file.write_text(content)
    return str(secrets_file)
