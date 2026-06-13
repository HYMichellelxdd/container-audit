"""CLI for container-audit."""

from __future__ import annotations

import argparse
import sys

from container_audit import __version__
from container_audit.scanner import Scanner
from container_audit.models import Severity
from container_audit.reporters.console import ConsoleReporter
from container_audit.reporters.json_out import JsonReporter
from container_audit.reporters.html_out import HtmlReporter


SEVERITY_ORDER = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container-audit",
        description="Container Audit - Lightweight container security auditor",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", help="Scan target type")

    docker_p = sub.add_parser("docker", help="Scan a Docker container")
    docker_p.add_argument("target", help="Container name or image")

    compose_p = sub.add_parser("compose", help="Scan a docker-compose file")
    compose_p.add_argument("file", help="Path to docker-compose.yml")

    k8s_p = sub.add_parser("k8s", help="Scan Kubernetes manifests")
    k8s_p.add_argument("path", help="Path to manifest file or directory")

    parser.add_argument("-f", "--format", choices=["console", "json", "html"], default="console")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                        help="Only show findings at or above this severity")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        default="high", help="Exit with code 1 if findings at or above this severity (default: high)")
    return parser


def filter_by_severity(findings, min_severity):
    """Filter findings to only include those at or above min_severity."""
    if not min_severity:
        return findings
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity.value, 0) >= min_level]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
        return 1

    scanner = Scanner()
    if args.command == "docker":
        result = scanner.scan_docker(args.target)
    elif args.command == "compose":
        result = scanner.scan_compose(args.file)
    elif args.command == "k8s":
        result = scanner.scan_kubernetes(args.path)
    else:
        return 1

    # Apply severity filter
    if hasattr(args, 'severity') and args.severity:
        result.findings = filter_by_severity(result.findings, args.severity)

    # Output report
    if args.format == "json":
        r = JsonReporter()
        if args.output:
            r.save(result, args.output)
            print(f"Report saved to: {args.output}")
        else:
            print(r.report(result))
    elif args.format == "html":
        r = HtmlReporter()
        if args.output:
            r.save(result, args.output)
            print(f"Report saved to: {args.output}")
        else:
            print(r.report(result))
    else:
        ConsoleReporter(verbose=args.verbose).report(result)

    # Exit code based on --fail-on threshold
    fail_level = SEVERITY_ORDER.get(args.fail_on, 3)
    for f in result.findings:
        if f.status.value == "fail" and SEVERITY_ORDER.get(f.severity.value, 0) >= fail_level:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
