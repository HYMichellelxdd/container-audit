# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within Container Audit, please send an email to contact@hyichellexdd.dev. All security vulnerabilities will be promptly addressed.

## Security Features

Container Audit itself is designed with security in mind:

- **No network requests** — All scans run locally
- **No data collection** — Your data never leaves your machine
- **Read-only scanning** — Never modifies containers or configurations
- **Minimal permissions** — Only requires access to Docker daemon or files being scanned

## Best Practices

When using Container Audit in CI/CD pipelines:

1. Run scans on every pull request
2. Set appropriate exit codes to block deployments with critical findings
3. Store reports as artifacts for audit trails
4. Review findings regularly and update security policies
