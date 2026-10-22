from __future__ import annotations

import math
import os
import re
from collections import Counter
from pathlib import Path

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".idea"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".gz",
             ".tar", ".7z", ".exe", ".dll", ".so", ".dylib", ".pyc", ".woff",
             ".woff2", ".ttf", ".mp4", ".mp3", ".sqlite", ".db"}
MAX_BYTES = 1_000_000

PATTERNS = [
    ("Private key block",
     re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
     Severity.CRITICAL, "CWE-798"),
    ("AWS access key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     Severity.CRITICAL, "CWE-798"),
    ("GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
     Severity.HIGH, "CWE-798"),
    ("Slack token",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     Severity.HIGH, "CWE-798"),
    ("Hardcoded credential",
     re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
     Severity.HIGH, "CWE-798"),
]

PLACEHOLDER_HINTS = ("example", "your_", "your-", "changeme", "xxxx",
                     "placeholder", "dummy", "<", "${", "{{")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(secret: str) -> str:
    return secret[:4] + "***" if len(secret) > 4 else "***"


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in SKIP_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


@register
class SecretScanner(BasePlugin):
    name = "secrets-basic"
    description = "Regex + entropy scan for hardcoded credentials"
    target_type = TargetType.OFFLINE
    priority = 20

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        root = Path(target).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Path not found: {root}")

        findings: list[Finding] = []
        for path in _iter_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(root))
            for lineno, line in enumerate(text.splitlines(), 1):
                if len(line) > 2000:
                    continue
                for label, pattern, severity, cwe in PATTERNS:
                    m = pattern.search(line)
                    if not m:
                        continue
                    secret = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                    if any(h in secret.lower() for h in PLACEHOLDER_HINTS):
                        continue
                    if label == "Hardcoded credential" and _entropy(secret) < 2.5:
                        continue
                    findings.append(Finding(
                        plugin=self.name,
                        title=label,
                        severity=severity,
                        target=target,
                        category="secret",
                        file=rel,
                        line=lineno,
                        evidence=line.strip()[:160].replace(secret, _redact(secret)),
                        description=f"Possible {label.lower()} committed in source.",
                        remediation="Move the secret to an environment variable or secrets "
                                    "manager, then rotate it.",
                        cwe=cwe,
                    ))
        return findings