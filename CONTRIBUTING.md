# Contributing to Container Audit

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/HYMichellelxdd/container-audit.git
cd container-audit
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Code Style

We use `ruff` for linting and formatting:

```bash
ruff check container_audit/
ruff format container_audit/
```

## Adding New Checks

1. Create a new method in the appropriate check module (`docker.py`, `kubernetes.py`, etc.)
2. Return a `Finding` object with severity and status
3. Add tests for the new check
4. Update the README check table

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Make your changes
4. Run tests (`pytest`)
5. Submit a pull request

## Reporting Issues

Please use the [GitHub Issues](https://github.com/HYMichellelxdd/container-audit/issues) page to report bugs or request features.
