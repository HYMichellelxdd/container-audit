"""JSON report output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from container_audit.scanner import ScanResult


class JsonReporter:
    """Export scan results as JSON."""

    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def report(self, result: ScanResult) -> str:
        """Return JSON string of scan results."""
        return json.dumps(
            result.to_dict(),
            indent=2 if self.pretty else None,
            ensure_ascii=False,
        )

    def save(self, result: ScanResult, output_path: str) -> Path:
        """Save JSON report to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.report(result))
        return path
