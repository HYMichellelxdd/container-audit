.PHONY: install test lint format build clean

install:
	pip install -e ".[dev]"

test:
	pytest --cov=container_audit

lint:
	ruff check container_audit/
	ruff format --check container_audit/

format:
	ruff check --fix container_audit/
	ruff format container_audit/

build:
	python -m build

clean:
	rm -rf dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +

scan-docker:
	container-audit docker $(TARGET)

scan-compose:
	container-audit compose $(TARGET)

scan-k8s:
	container-audit k8s $(TARGET)

scan-secrets:
	container-audit secrets $(TARGET)
