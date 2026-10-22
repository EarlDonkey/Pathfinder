from __future__ import annotations

import argparse
import sys

from vuln_toolkit.core.engine import ScanResult, ScannerOrchestrator
from vuln_toolkit.core.logger import setup_logging
from vuln_toolkit.core.plugin_base import TargetType, get_registry
from vuln_toolkit.core.reporter import emit


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["console", "json"], default="console")
    common.add_argument("-o", "--output", help="Write report to file")
    common.add_argument("--plugin-dir", action="append", default=[], help="Extra plugin directory (repeatable)")
    common.add_argument("-v", "--verbose", action="count", default=0)

    parser = argparse.ArgumentParser(prog="vuln-toolkit", description="Modular dual-mode vulnerability toolkit")
    sub = parser.add_subparsers(dest="mode", required=True)

    off = sub.add_parser("offline", parents=[common], help="Static analysis of a local path")
    off.add_argument("-p", "--path", required=True)

    on = sub.add_parser("online", parents=[common], help="Network/web scan of a host or URL")
    on.add_argument("-t", "--target", required=True)

    both = sub.add_parser("all", parents=[common], help="Run offline and online modes")
    both.add_argument("-p", "--path", required=True)
    both.add_argument("-t", "--target", required=True)

    sub.add_parser("plugins", parents=[common], help="List registered plugins")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    if args.mode == "plugins":
        ScannerOrchestrator(args.plugin_dir).discover()
        for name, cls in sorted(get_registry().items()):
            print(f"{name:24} [{cls.target_type.value:7}] {cls.description}")
        return 0

    orch = ScannerOrchestrator(args.plugin_dir)

    if args.mode == "offline":
        result = orch.run(TargetType.OFFLINE, args.path)
    elif args.mode == "online":
        result = orch.run(TargetType.ONLINE, args.target)
    else:
        off = orch.run(TargetType.OFFLINE, args.path)
        on = orch.run(TargetType.ONLINE, args.target)
        result = ScanResult(
            target=f"{args.path} + {args.target}",
            mode="all",
            findings=off.findings + on.findings,
            errors=off.errors + on.errors,
            plugins_run=off.plugins_run + on.plugins_run,
            duration=off.duration + on.duration,
        )

    emit(result, fmt=args.format, output=args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())