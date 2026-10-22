from __future__ import annotations

import importlib.util
import json
import logging
import subprocess  # nosec B404 — pip-audit invoked by module name, no shell
import sys
from pathlib import Path

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

LOCKFILES = ["requirements.txt", "requirements.lock", "requirements-dev.txt",
             "Pipfile.lock", "poetry.lock", "pyproject.toml"]


@register
class PipAuditPlugin(BasePlugin):
    name = "pip-audit"
    description = "Dependency CVE audit via pip-audit (if installed)"
    target_type = TargetType.OFFLINE
    priority = 60

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        if importlib.util.find_spec("pip_audit") is None:
            log.info("pip-audit not installed; install with `pip install pip-audit` to enable")
            return []
        root = Path(target).resolve()
        if not root.exists():
            return []

        req = self._find_requirements(root)
        cmd = [sys.executable, "-m", "pip_audit", "-f", "json",
               "--progress-spinner", "off"]
        if req:
            cmd += ["-r", str(req)]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # nosec B603
        except Exception as exc:
            log.warning("pip-audit execution failed: %s", exc)
            return []

        if not proc.stdout.strip():
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        deps = data if isinstance(data, list) else data.get("dependencies", [])
        rel_req = str(req.relative_to(root)) if req and root.is_dir() else (req.name if req else None)
        findings: list[Finding] = []
        for dep in deps:
            name = dep.get("name", "?")
            version = dep.get("version", "?")
            for vuln in dep.get("vulns", []):
                vid = vuln.get("id", "")
                is_cve = vid.startswith("CVE-")
                fix = vuln.get("fix_versions") or []
                findings.append(Finding(
                    plugin=self.name,
                    title=f"{name} {version}: {vid}",
                    severity=Severity.MEDIUM,  # enriched upward via KEV/EPSS
                    target=target,
                    category="dependency",
                    file=rel_req,
                    cve=vid if is_cve else None,
                    description=(vuln.get("description") or "")[:500]
                                or f"Dependency {name} {version} is affected by {vid}.",
                    remediation=f"Upgrade {name} to {' or '.join(fix)}." if fix
                                else f"Upgrade {name} to the latest patched version.",
                    references=vuln.get("aliases", []) or [],
                ))
        return findings

    @staticmethod
    def _find_requirements(root: Path) -> Path | None:
        candidates = [root / n for n in LOCKFILES] if root.is_dir() else [root]
        for c in candidates:
            if c.is_file():
                return c
        return None