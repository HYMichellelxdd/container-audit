"""Shared utilities."""

from __future__ import annotations

import os
import subprocess
from typing import Any


def run_command(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"


def is_docker_running() -> bool:
    """Check if Docker daemon is accessible."""
    code, _, _ = run_command(["docker", "info"], timeout=5)
    return code == 0


def file_age_hours(path: str) -> float:
    """Get file age in hours."""
    import time
    mtime = os.path.getmtime(path)
    return (time.time() - mtime) / 3600
# noqa
