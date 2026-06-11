"""Command-line interface for container-audit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from container_audit import __version__
from container_audit.scanner import Scanner
from container_audit.reporters.console import ConsoleReporter
from container_audit.reporters.json_out import JsonReporter
from container_audit.reporters.html_out import HtmlReporter


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="container-audit",
        description="🔒 Container Audit - Lightweight container security auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  container-audit docker my-container
  container-audit compose docker-compose.yml
  container-audit k8s ./k8s-manifests/
  container-audit secrets ./src/ --format json -o report.json
  container-audit docker my-container --format html -o report.html
""",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Scan target type")

    # Docker scan
    docker_parser = subparsers.add_parser("docker", help="Scan a Docker container or image")
    docker_parser.add_argument("target", help="Container name/ID or image name")

    # Compose scan
    compose_parser = subparsers.add_parser("compose", help="Scan a docker-compose file")
    compose_parser.add_argument("file", help="Path to docker-compose.yml")

    # Kubernetes scan
    k8s_parser = subparsers.add_parser("k8s", help="Scan Kubernetes manifests")
    k8s_parser.add_argument("path", help="Path to manifest file or directory")

    # Secrets scan
    secrets_parser = subparsers.add_parser("secrets", help="Scan for leaked secrets")
    secrets_parser.add_argument("path", help="File or directory to scan")

    # Global options
    parser.add_argument("-f", "--format", choices=["console", "json", "html"], default="console",
                        help="Output format (default: console)")
    parser.add_argument("-o", "--output", help="Output file path (for json/html formats)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output including evidence")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    scanner = Scanner()

    # Execute scan
    if args.command == "docker":
        result = scanner.scan_docker(args.target)
    elif args.command == "compose":
        result = scanner.scan_compose(args.file)
    elif args.command == "k8s":
        result = scanner.scan_kubernetes(args.path)
    elif args.command == "secrets":
        result = scanner.scan_secrets(args.path)
    else:
        parser.print_help()
        return 1

    # Generate report
    if args.format == "json":
        reporter = JsonReporter()
        if args.output:
            path = reporter.save(result, args.output)
            print(f"Report saved to: {path}")
        else:
            print(reporter.report(result))
    elif args.format == "html":
        reporter = HtmlReporter()
        if args.output:
            path = reporter.save(result, args.output)
            print(f"Report saved to: {path}")
        else:
            print(reporter.report(result))
    else:
        reporter = ConsoleReporter(verbose=args.verbose)
        reporter.report(result)

    # Exit code based on findings
    if result.critical_count > 0:
        return 2
    elif result.high_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
