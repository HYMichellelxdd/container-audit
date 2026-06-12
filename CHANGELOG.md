# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-06-12

### Added
- Docker container security checks (14 checks)
  - Privileged mode detection
  - Docker socket mount detection
  - Root user detection
  - Dangerous capabilities detection
  - Port exposure checks
  - Environment variable secret detection
  - Read-only root filesystem check
  - Resource limits validation
  - Healthcheck configuration
  - AppArmor/Seccomp profile checks
  - PID/IPC/Network host namespace checks
- Docker Compose file scanning
- Kubernetes manifest security checks
  - Privileged container detection
  - SecurityContext validation
  - ServiceAccount token automount checks
  - Host namespace detection
  - HostPath volume detection
  - RBAC overprivilege detection
  - NetworkPolicy validation
  - Ingress TLS checks
- Secret and credential detection
  - API keys, AWS keys, GitHub tokens
  - Private keys, passwords, connection strings
  - JWT tokens, GCP/Azure credentials
- CLI with subcommands (docker, compose, k8s, secrets)
- Console reporter with Rich formatting
- JSON report output
- HTML report with dark theme
- Security score calculation (0-100)
- GitHub Actions CI pipeline
- Comprehensive test suite
