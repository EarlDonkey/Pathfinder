from __future__ import annotations

import argparse
import sys

from vuln_toolkit.core.engine import ScanResult, ScannerOrchestrator
from vuln_toolkit.core.logger import setup_logging
from vuln_toolkit.core.plugin_base import TargetType, get_registry
from vuln_toolkit.core.reporter import emit
from vuln_toolkit.core.store import save_scan, get_previous_scan, get_latest_scan
from vuln_toolkit.core.differ import diff_scans


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["console", "json", "html"], default="console")
    common.add_argument("-o", "--output", help="Write report to file")
    common.add_argument("--plugin-dir", action="append", default=[],
                        help="Extra plugin directory (repeatable)")
    common.add_argument("--no-enrich", action="store_true",
                        help="Skip CVE/KEV/EPSS enrichment")
    common.add_argument("--no-suppress", action="store_true",
                        help="Ignore .vulnignore file")
    common.add_argument("--no-save", action="store_true",
                        help="Do not save results to the local database")
    common.add_argument("-v", "--verbose", action="count", default=0)

    parser = argparse.ArgumentParser(
        prog="vuln-toolkit",
        description="Modular dual-mode vulnerability toolkit",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    off = sub.add_parser("offline", parents=[common],
                         help="Static analysis of a local path")
    off.add_argument("-p", "--path", required=True)

    on = sub.add_parser("online", parents=[common],
                        help="Network/web scan of a host or URL")
    on.add_argument("-t", "--target", required=True)

    both = sub.add_parser("all", parents=[common],
                          help="Run offline and online modes")
    both.add_argument("-p", "--path", required=True)
    both.add_argument("-t", "--target", required=True)

    diff = sub.add_parser("diff", help="Compare the two most recent scans for a target")
    diff.add_argument("-t", "--target", required=True)

    sub.add_parser("plugins", parents=[common], help="List registered plugins")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    
    # Diff mode doesn't run plugins, so handle it early
    if args.mode == "diff":
        latest = get_latest_scan(args.target)
        if not latest:
            print(f"[!] No scans found for {args.target}. Run a scan first.", file=sys.stderr)
            return 1
        
        previous = get_previous_scan(args.target)
        if not previous:
            print(f"[!] Only one scan found for {args.target}. Need at least two to diff.", file=sys.stderr)
            return 1
            
        old_id, old_findings = previous
        new_id, new_findings = latest
        
        result = diff_scans(args.target, old_findings, new_findings)
        result.print_summary()
        return 0

    setup_logging(args.verbose)

    if args.mode == "plugins":
        ScannerOrchestrator(args.plugin_dir).discover()
        for name, cls in sorted(get_registry().items()):
            print(f"{name:24} [{cls.target_type.value:7}] {cls.description}")
        return 0

    orch = ScannerOrchestrator(
        args.plugin_dir,
        enrich=not args.no_enrich,
        use_suppressions=not args.no_suppress,
    )

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
            suppressed=off.suppressed + on.suppressed,
            duration=off.duration + on.duration,
        )

    emit(result, fmt=args.format, output=args.output)
    
    if not args.no_save:
        try:
            save_scan(result)
            if args.verbose > 0:
                print(f"[+] Scan saved to local database", file=sys.stderr)
        except Exception as e:
            print(f"[!] Failed to save scan: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())