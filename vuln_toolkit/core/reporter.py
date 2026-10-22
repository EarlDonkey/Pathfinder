from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

from vuln_toolkit.core.engine import ScanResult
from vuln_toolkit.core.plugin_base import Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;37m",
}
_RESET = "\033[0m"


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def render_console(result: ScanResult) -> str:
    color = _use_color()
    findings = result.sorted_findings()
    counts = Counter(f.severity for f in findings)
    lines: list[str] = []

    lines.append("=" * 64)
    lines.append(f"Target : {result.target}")
    lines.append(f"Mode   : {result.mode}")
    lines.append(f"Time   : {result.duration:.2f}s | Plugins: {len(result.plugins_run)} | Errors: {len(result.errors)}")
    summary = ", ".join(f"{s.value}={counts.get(s, 0)}" for s in reversed(list(Severity)))
    lines.append(f"Results: {len(findings)} finding(s) ({summary})")
    lines.append("=" * 64)

    for f in findings:
        tag = f"[{f.severity.value.upper():^8}]"
        if color:
            tag = f"{_COLORS[f.severity]}{tag}{_RESET}"
        location = ""
        if f.file:
            location = f" {f.file}" + (f":{f.line}" if f.line else "")
        elif f.line:
            location = f" line {f.line}"
        lines.append(f"{tag} {f.title}{location}")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence}")
        if f.remediation:
            lines.append(f"           fix: {f.remediation}")
        lines.append("")

    for err in result.errors:
        lines.append(f"[ ERROR  ] {err['plugin']}: {err['error']}")

    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ScanResult) -> str:
    payload = {
        "scan": {
            "target": result.target,
            "mode": result.mode,
            "duration_seconds": round(result.duration, 4),
            "plugins_run": result.plugins_run,
            "errors": result.errors,
        },
        "summary": {
            sev.value: sum(1 for f in result.findings if f.severity == sev)
            for sev in Severity
        },
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }
    return json.dumps(payload, indent=2)


def emit(result: ScanResult, fmt: str = "console", output: str | None = None) -> None:
    text = render_json(result) if fmt == "json" else render_console(result)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"[+] Report written to {output}", file=sys.stderr)
    else:
        print(text)