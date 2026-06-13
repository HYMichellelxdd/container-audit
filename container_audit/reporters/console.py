"""Rich console reporter for terminal output."""

from __future__ import annotations

from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from container_audit.models import ScanResult, Severity, Status


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

STATUS_SYMBOLS = {
    Status.PASS: "[green]✓[/green]",
    Status.FAIL: "[bold red]✗[/bold red]",
    Status.WARN: "[yellow]⚠[/yellow]",
    Status.SKIP: "[dim]○[/dim]",
}


class ConsoleReporter:
    """Pretty-print scan results to terminal."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.console = Console() if HAS_RICH else None

    def report(self, result: ScanResult) -> None:
        """Print scan report to console."""
        if not HAS_RICH:
            self._report_plain(result)
            return

        # Header
        score_color = "green" if result.score >= 80 else "yellow" if result.score >= 50 else "red"
        header = Text()
        header.append("  Container Audit Report\n", style="bold")
        header.append(f"  Target: {result.target}\n")
        header.append(f"  Scan Type: {result.scan_type}\n")
        header.append(f"  Score: ", style="bold")
        header.append(f"{result.score}/100", style=f"bold {score_color}")
        self.console.print(Panel(header, title="[bold]Security Report[/bold]", border_style="blue"))

        # Summary
        summary = Table(title="Summary", show_header=True, header_style="bold")
        summary.add_column("Severity", style="bold")
        summary.add_column("Failed", justify="right")
        summary.add_column("Passed", justify="right")
        summary.add_column("Warnings", justify="right")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            sev_findings = [f for f in result.findings if f.severity == sev]
            if sev_findings:
                summary.add_row(
                    Text(sev.value.upper(), style=SEVERITY_COLORS[sev]),
                    str(sum(1 for f in sev_findings if f.status == Status.FAIL)),
                    str(sum(1 for f in sev_findings if f.status == Status.PASS)),
                    str(sum(1 for f in sev_findings if f.status == Status.WARN)),
                )
        self.console.print(summary)

        # Findings
        if result.findings:
            self.console.print("\n[bold]Findings:[/bold]")
            for finding in result.findings:
                symbol = STATUS_SYMBOLS.get(finding.status, "?")
                sev_color = SEVERITY_COLORS.get(finding.severity, "white")
                line = f"  {symbol} [{sev_color}]{finding.severity.value.upper():>8}[/{sev_color}]  {finding.title}"
                if finding.status == Status.FAIL and finding.remediation:
                    line += f"\n       [dim]→ {finding.remediation}[/dim]"
                if self.verbose and finding.evidence:
                    line += f"\n       [dim]Evidence: {finding.evidence}[/dim]"
                self.console.print(line)

        # Footer
        footer = Text()
        footer.append(f"\n  Total: {len(result.findings)} checks | ", style="dim")
        footer.append(f"Passed: {result.total_passed} ", style="green")
        footer.append(f"Failed: {result.total_failed} ", style="red")
        footer.append(f"Warnings: {result.total_warnings} ", style="yellow")
        self.console.print(Panel(footer, border_style="dim"))

    def _report_plain(self, result: ScanResult) -> None:
        """Fallback plain text output."""
        print(f"\n{'='*60}")
        print(f"  Container Audit Report")
        print(f"  Target: {result.target}")
        print(f"  Scan Type: {result.scan_type}")
        print(f"  Score: {result.score}/100")
        print(f"{'='*60}")
        print(f"\n  Passed: {result.total_passed} | Failed: {result.total_failed} | Warnings: {result.total_warnings}")
        print(f"\n  Findings:")
        for f in result.findings:
            status = "PASS" if f.status == Status.PASS else "FAIL" if f.status == Status.FAIL else "WARN"
            print(f"    [{status:>4}] [{f.severity.value.upper():>8}] {f.title}")
            if f.status == Status.FAIL and f.remediation:
                print(f"           -> {f.remediation}")
        print(f"{'='*60}")
