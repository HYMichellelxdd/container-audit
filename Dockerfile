FROM python:3.12-slim

LABEL maintainer="HYMichellexdd"
LABEL description="Container Audit - Lightweight container security auditor"

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy source
COPY container_audit/ container_audit/

# Default entrypoint
ENTRYPOINT ["container-audit"]
