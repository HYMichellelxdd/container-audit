<p align="center">
  <img src="https://img.shields.io/badge/🔒-Container%20Audit-blueviolet?style=for-the-badge" alt="Container Audit"/>
</p>

<h1 align="center">Container Audit</h1>

<p align="center">
  <strong>Lightweight container security auditor for Docker and Kubernetes</strong>
</p>

<p align="center">
  <a href="https://github.com/HYMichellexdd/container-audit/actions/workflows/ci.yml"><img src="https://github.com/HYMichellexdd/container-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/HYMichellexdd/container-audit/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://pypi.org/project/container-audit/"><img src="https://img.shields.io/pypi/v/container-audit.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/container-audit/"><img src="https://img.shields.io/pypi/pyversions/container-audit.svg" alt="Python"></a>
</p>

---

## ✨ Features

**Container Audit** is a fast, lightweight security scanner that helps developers and DevSecOps teams identify misconfigurations in Docker and Kubernetes environments before they become vulnerabilities.

- 🐳 **Docker Security** — 14 checks covering privileged mode, capabilities, secrets, network exposure, and more
- ☸️ **Kubernetes Compliance** — Pod Security, RBAC, NetworkPolicy, and manifest best practices
- 🔍 **Secret Detection** — Scan files for leaked API keys, private keys, passwords, and connection strings
- 📊 **Multiple Reports** — Terminal (Rich), JSON, and HTML output with dark theme
- ⚡ **Security Score** — 0-100 score based on severity-weighted findings
- 🔌 **CI/CD Ready** — Exit codes and JSON output for pipeline integration

## 🚀 Quick Start

### Installation

```bash
pip install container-audit
```

Or from source:

```bash
git clone https://github.com/HYMichellexdd/container-audit.git
cd container-audit
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Scan a running Docker container
container-audit docker my-container

# Scan a docker-compose file
container-audit compose docker-compose.yml

# Scan Kubernetes manifests
container-audit k8s ./k8s-manifests/

# Scan for secrets in source code
container-audit secrets ./src/
```

### Output Formats

```bash
# JSON output (for CI/CD pipelines)
container-audit docker my-container -f json -o report.json

# HTML report (dark theme, great for sharing)
container-audit docker my-container -f html -o report.html

# Verbose terminal output with evidence
container-audit docker my-container -v
```

## 📋 Security Checks

### Docker (14 checks)

| Check | Severity | Description |
|-------|----------|-------------|
| `DOCKER-001` | 🔴 CRITICAL | Privileged container detection |
| `DOCKER-002` | 🔴 CRITICAL | Docker socket mount detection |
| `DOCKER-003` | 🟡 MEDIUM | Running as root user |
| `DOCKER-004` | 🔴 HIGH | Dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.) |
| `DOCKER-005` | 🟡 MEDIUM | Ports exposed on 0.0.0.0 |
| `DOCKER-006` | 🔴 HIGH | Secrets in environment variables |
| `DOCKER-007` | 🔵 LOW | Writable root filesystem |
| `DOCKER-008` | 🟡 MEDIUM | Missing resource limits (memory/CPU/PIDs) |
| `DOCKER-009` | 🔵 LOW | No healthcheck configured |
| `DOCKER-010` | 🔵 LOW | AppArmor profile status |
| `DOCKER-011` | 🔵 LOW | Seccomp profile status |
| `DOCKER-012` | 🔴 HIGH | Host PID namespace sharing |
| `DOCKER-013` | 🟡 MEDIUM | Host IPC namespace sharing |
| `DOCKER-014` | 🔴 HIGH | Host network mode |

### Kubernetes

| Check | Severity | Description |
|-------|----------|-------------|
| `K8S-PRIV-*` | 🔴 CRITICAL | Privileged containers in workloads |
| `K8S-ROOT-*` | 🟡 MEDIUM | Containers running as root |
| `K8S-CAPS-*` | 🔴 HIGH | Dangerous capabilities added |
| `K8S-SA-TOKEN` | 🟡 MEDIUM | ServiceAccount token auto-mounting |
| `K8S-HNET` | 🔴 HIGH | Host network enabled |
| `K8S-HPID` | 🔴 HIGH | Host PID namespace |
| `K8S-HOSTPATH` | 🔴 HIGH | HostPath volumes mounted |
| `K8S-RBAC-*` | 🔴 HIGH | Overprivileged RBAC rules |
| `K8S-NS-*` | 🟡 MEDIUM | Namespace configuration checks |
| `K8S-ING-TLS-*` | 🔴 HIGH | Ingress without TLS |
| `K8S-NP-*` | 🟡 MEDIUM | NetworkPolicy validation |

### Secrets Detection

| Pattern | Severity | Description |
|---------|----------|-------------|
| API Keys | 🔴 CRITICAL | Generic API key patterns |
| AWS Keys | 🔴 CRITICAL | AWS access/secret keys |
| GitHub Tokens | 🔴 CRITICAL | GitHub PATs and tokens |
| Private Keys | 🔴 CRITICAL | RSA/EC/DSA private keys |
| Passwords | 🔴 CRITICAL | Hardcoded passwords |
| Connection Strings | 🔴 CRITICAL | Database/message broker URIs |
| JWT Tokens | 🔴 CRITICAL | JSON Web Tokens |
| GCP/Azure | 🔴 CRITICAL | Cloud provider credentials |

## 📊 Report Example

```
╭──────────── Security Report ────────────╮
│  Container Audit Report                 │
│  Target: my-container                   │
│  Scan Type: docker                      │
│  Score: 35/100                          │
╰─────────────────────────────────────────╯

┌──────────────────────────────────────────────┐
│           Summary                            │
├──────────┬────────┬────────┬─────────────────┤
│ Severity │ Failed │ Passed │ Warnings        │
├──────────┼────────┼────────┼─────────────────┤
│ CRITICAL │      2 │      0 │               0 │
│ HIGH     │      3 │      1 │               0 │
│ MEDIUM   │      2 │      1 │               1 │
│ LOW      │      1 │      2 │               2 │
└──────────┴────────┴────────┴─────────────────┘

Findings:
  ✗  CRITICAL  Privileged container
       → Remove --privileged flag. Use specific capabilities instead.
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
    container-audit docker ${{ env.IMAGE }} -f json -o scan-results.json
    # Fail CI on critical findings
    container-audit docker ${{ env.IMAGE }}
```

### GitLab CI

```yaml
security_scan:
  image: python:3.12-slim
  script:
    - pip install container-audit
    - container-audit k8s ./k8s/ -f json -o report.json
  artifacts:
    reports:
      container_scanning: report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high findings |
| `1` | High severity findings present |
| `2` | Critical severity findings present |

## 🛡️ Why Container Audit?

| Feature | Container Audit | Trivy | Grype | Snyk |
|---------|----------------|-------|-------|------|
| Docker config audit | ✅ | ❌ | ❌ | ❌ |
| Compose file scan | ✅ | ❌ | ❌ | ❌ |
| K8s manifest check | ✅ | ⚠️ Limited | ❌ | ⚠️ Limited |
| Secret detection | ✅ | ✅ | ❌ | ✅ |
| CI/CD friendly | ✅ | ✅ | ✅ | ✅ |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| Lightweight (<1s) | ✅ | ⚠️ | ✅ | ❌ |

## 📁 Project Structure

```
container-audit/
├── container_audit/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── scanner.py           # Core scanning engine
│   ├── utils.py             # Shared utilities
│   ├── checks/
│   │   ├── docker.py        # Docker security checks
│   │   ├── kubernetes.py    # K8s manifest checks
│   │   ├── network.py       # Network exposure checks
│   │   └── secrets.py       # Secret detection
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

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-check`)
3. Commit your changes (`git commit -m 'Add amazing security check'`)
4. Push to the branch (`git push origin feature/amazing-check`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [GitHub Repository](https://github.com/HYMichellexdd/container-audit)
- [Issue Tracker](https://github.com/HYMichellexdd/container-audit/issues)
- [PyPI Package](https://pypi.org/project/container-audit/)

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/HYMichellexdd">HYMichellexdd</a>
</p>
