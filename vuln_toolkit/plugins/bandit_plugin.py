from __future__ import annotations

import importlib.util
import json
import logging
import subprocess  # nosec B404 — bandit invoked by module name, no shell, no untrusted input
import sys
from pathlib import Path

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

_SEV_MAP = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}


def _extract_evidence(code: str | None, line_number: int | None) -> str | None:
    """Bandit's `code` field is a multi-line snippet; pick the line matching `line_number`."""
    if not code:
        return None
    lines = code.splitlines()
    if line_number is not None:
        for line in lines:
            stripped = line.lstrip()
            prefix, _, rest = stripped.partition(" ")
            if prefix.isdigit() and int(prefix) == line_number:
                return rest.strip()[:160]
    return lines[0].strip()[:160] if lines else None


@register
class BanditPlugin(BasePlugin):
    name = "bandit"
    description = "Bandit SAST (if installed)"
    target_type = TargetType.OFFLINE
    priority = 50

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        if importlib.util.find_spec("bandit") is None:
            log.info("bandit not installed; install with `pip install bandit` to enable")
            return []
        root = Path(target).resolve()
        if not root.exists():
            return []

        cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", "--exit-zero"]
        cmd += ["-r", str(root)] if root.is_dir() else [str(root)]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # nosec B603
        except Exception as exc:
            log.warning("bandit execution failed: %s", exc)
            return []

        if not proc.stdout.strip():
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            log.warning("bandit output was not JSON; skipping")
            return []

        findings: list[Finding] = []
        for r in data.get("results", []):
            filepath = r.get("filename", "")
            try:
                rel = str(Path(filepath).relative_to(root)) if root.is_dir() else Path(filepath).name
            except ValueError:
                rel = filepath
            cwe = None
            if isinstance(r.get("issue_cwe"), dict):
                cwe = f"CWE-{r['issue_cwe'].get('id')}"
            findings.append(Finding(
                plugin=self.name,
                title=f"{r.get('test_id', 'BXXX')}: {r.get('test_name', 'issue')}",
                severity=_SEV_MAP.get(r.get("issue_severity", "LOW"), Severity.LOW),
                target=target,
                category="sast",
                file=rel,
                line=r.get("line_number"),
                evidence=_extract_evidence(r.get("code"), r.get("line_number")),
                description=r.get("issue_text", ""),
                remediation="See the Bandit rule documentation for remediation guidance.",
                cwe=cwe,
                references=[r["more_info"]] if r.get("more_info") else [],
            ))
        return findings