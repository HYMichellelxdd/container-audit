<p align="center">
  <img src="https://img.shields.io/badge/🔒-Container%20Audit-blueviolet?style=for-the-badge" alt="Container Audit"/>
</p>

<h1 align="center">Container Audit</h1>

<p align="center">
  <strong>Lightweight container security auditor for Docker and Kubernetes</strong>
</p>

<p align="center">
  <a href="https://github.com/HYMichellelxdd/container-audit/actions/workflows/ci.yml"><img src="https://github.com/HYMichellelxdd/container-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/HYMichellelxdd/container-audit/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://pypi.org/project/container-audit/"><img src="https://img.shields.io/pypi/v/container-audit.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/container-audit/"><img src="https://img.shields.io/pypi/pyversions/container-audit.svg" alt="Python"></a>
</p>

---

## ✨ Features

**Container Audit** is a fast, lightweight security scanner that helps developers and DevSecOps teams identify misconfigurations in Docker and Kubernetes environments.

- 🐳 **Docker Security** — 16 checks covering privileged mode, capabilities, secrets, socket permissions, and more
- ☸️ **Kubernetes Compliance** — Pod Security, RBAC, NetworkPolicy, security context best practices
- 🎚️ **Severity Filtering** — Filter findings by severity level
- ⚡ **Fail-on Threshold** — Configurable exit code based on severity for CI/CD
- 📊 **Multiple Reports** — Terminal (Rich), JSON, and HTML output
- ⚡ **Security Score** — 0-100 score based on severity-weighted findings

## 🚀 Quick Start

### Installation

```bash
pip install container-audit
```

### Basic Usage

```bash
# Scan a Docker container
container-audit docker my-container

# Scan a docker-compose file
container-audit compose docker-compose.yml

# Scan Kubernetes manifests
container-audit k8s ./k8s-manifests/

# Only show high and critical findings
container-audit docker my-container --severity high

# Exit with error only on critical findings (for CI)
container-audit docker my-container --fail-on critical
```

### Output Formats

```bash
# JSON output (for CI/CD pipelines)
container-audit docker my-container -f json -o report.json

# HTML report (dark theme)
container-audit docker my-container -f html -o report.html

# Verbose terminal output
container-audit docker my-container -v
```

## 📋 Security Checks

### Docker (16 checks)

| Check | Severity | Description |
|-------|----------|-------------|
| `DOCKER-001` | 🔴 CRITICAL | Privileged container detection |
| `DOCKER-002` | 🔴 CRITICAL | Docker socket mount detection |
| `DOCKER-003` | 🟡 MEDIUM | Running as root user |
| `DOCKER-004` | 🔴 HIGH | Dangerous capabilities (SYS_ADMIN, NET_ADMIN) |
| `DOCKER-005` | 🟡 MEDIUM | Ports exposed on 0.0.0.0 |
| `DOCKER-006` | 🔴 HIGH | Secrets in environment variables |
| `DOCKER-007` | 🔵 LOW | Writable root filesystem |
| `DOCKER-008` | 🟡 MEDIUM | Missing resource limits |
| `DOCKER-009` | 🔵 LOW | No healthcheck configured |
| `DOCKER-010` | 🔵 LOW | AppArmor profile status |
| `DOCKER-011` | 🔵 LOW | Seccomp profile status |
| `DOCKER-012` | 🔴 HIGH | Host PID namespace |
| `DOCKER-013` | 🟡 MEDIUM | Host IPC namespace |
| `DOCKER-014` | 🔴 HIGH | Host network mode |
| `DOCKER-015` | 🔴 HIGH | Docker socket permissions |

### Kubernetes

| Check | Severity | Description |
|-------|----------|-------------|
| `K8S-PRIV-*` | 🔴 CRITICAL | Privileged containers |
| `K8S-ROOT-*` | 🟡 MEDIUM | Running as root |
| `K8S-CAPS-*` | 🔴 HIGH | Dangerous capabilities |
| `K8S-PE-*` | 🟡 MEDIUM | Privilege escalation not disabled |
| `K8S-SECCOMP-*` | 🔵 LOW | No seccomp profile |
| `K8S-CAPDROP-*` | 🟡 MEDIUM | Capabilities not dropped |
| `K8S-SA-TOKEN` | 🟡 MEDIUM | ServiceAccount token auto-mounted |
| `K8S-HNET` | 🔴 HIGH | Host network enabled |
| `K8S-HOSTPATH` | 🔴 HIGH | HostPath volumes |
| `K8S-RBAC-*` | 🔴 HIGH | Overprivileged RBAC |

### Docker Compose

| Check | Severity | Description |
|-------|----------|-------------|
| `COMPOSE-*-001` | 🔴 CRITICAL | Privileged mode |
| `COMPOSE-*-002` | 🔴 CRITICAL | Docker socket mounted |
| `COMPOSE-*-003` | 🟡 MEDIUM | Running as root |
| `COMPOSE-*-004` | 🔴 HIGH | Dangerous capabilities |
| `COMPOSE-*-HEALTH` | 🔵 LOW | Healthcheck check |
| `COMPOSE-*-RESTART` | 🔵 LOW | Restart policy |
| `COMPOSE-*-ROFS` | 🔵 LOW | Read-only filesystem |

## 📊 Report Example

```
╭──────────── Security Report ────────────╮
│  Container Audit Report                 │
│  Target: my-container                   │
│  Scan Type: docker                      │
│  Score: 35/100                          │
╰─────────────────────────────────────────╯

Findings:
  ✗  CRITICAL  Privileged container
       → Remove --privileged flag.
  ✗  CRITICAL  Docker socket mounted
       → Avoid mounting Docker socket.
  ✗     HIGH  Dangerous capabilities added
       → Remove unnecessary capabilities.
  ✓     HIGH  Host PID namespace
  ✗   MEDIUM  Running as root
       → Set USER directive in Dockerfile.
```

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
- name: Container Security Scan
  run: |
    pip install container-audit
    container-audit docker ${{ env.IMAGE }} --fail-on critical
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings above threshold |
| `1` | Findings at or above `--fail-on` threshold |

## 📁 Project Structure

```
container-audit/
├── container_audit/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── scanner.py           # Core scanning engine
│   ├── models.py            # Data models
│   ├── checks/
│   │   ├── docker.py        # Docker security checks
│   │   ├── kubernetes.py    # K8s manifest checks
│   │   └── network.py       # Network exposure checks
│   └── reporters/
│       ├── console.py       # Rich terminal output
│       ├── json_out.py      # JSON report
│       └── html_out.py      # HTML report
├── tests/
├── .github/workflows/ci.yml
├── pyproject.toml
├── LICENSE
└── README.md
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE)

## 🔗 Links

- [GitHub Repository](https://github.com/HYMichellelxdd/container-audit)
- [PyPI Package](https://pypi.org/project/container-audit/)
- [Issue Tracker](https://github.com/HYMichellelxdd/container-audit/issues)

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/HYMichellelxdd">HYMichellexdd</a>
</p>
