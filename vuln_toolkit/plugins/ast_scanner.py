from __future__ import annotations

import ast
from pathlib import Path

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", "build", "dist", "node_modules"}

NAME_RULES = {
    "eval":       (Severity.HIGH,   "CWE-95",  "Dynamic code evaluation via eval()."),
    "exec":       (Severity.HIGH,   "CWE-95",  "Dynamic code execution via exec()."),
    "compile":    (Severity.MEDIUM, "CWE-95",  "Dynamic code compilation via compile()."),
    "__import__": (Severity.MEDIUM, "CWE-94",  "Dynamic import via __import__()."),
}
ATTR_RULES = {
    "os.system":     (Severity.MEDIUM, "CWE-78",  "Shell execution via os.system()."),
    "os.popen":      (Severity.MEDIUM, "CWE-78",  "Shell execution via os.popen()."),
    "pickle.loads":  (Severity.HIGH,   "CWE-502", "Unsafe deserialization via pickle.loads()."),
    "pickle.load":   (Severity.HIGH,   "CWE-502", "Unsafe deserialization via pickle.load()."),
    "marshal.loads": (Severity.HIGH,   "CWE-502", "Unsafe deserialization via marshal.loads()."),
}
SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        base = node.value
        if isinstance(base, ast.Name):
            return f"{base.id}.{node.attr}"
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, source: str, relpath: str, target: str, plugin: str) -> None:
        self.source = source
        self.relpath = relpath
        self.target = target
        self.plugin = plugin
        self.findings: list[Finding] = []

    def _add(self, node: ast.AST, severity: Severity, cwe: str, title: str) -> None:
        segment = ast.get_source_segment(self.source, node) or ""
        evidence = segment.strip().splitlines()[0][:160] if segment else None
        self.findings.append(Finding(
            plugin=self.plugin,
            title=title,
            severity=severity,
            target=self.target,
            category="insecure-code",
            file=self.relpath,
            line=getattr(node, "lineno", None),
            evidence=evidence,
            cwe=cwe,
            remediation="Avoid dynamic execution/deserialization on untrusted input; "
                        "use safe alternatives.",
        ))

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in NAME_RULES:
            sev, cwe, title = NAME_RULES[node.func.id]
            self._add(node, sev, cwe, title)

        attr = _attr_name(node.func)
        if attr in ATTR_RULES:
            sev, cwe, title = ATTR_RULES[attr]
            self._add(node, sev, cwe, title)

        if attr and attr.startswith("subprocess.") and attr.split(".", 1)[1] in SUBPROCESS_FUNCS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(node, Severity.MEDIUM, "CWE-78", "subprocess call with shell=True")

        if attr == "yaml.load":
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
            safe = isinstance(loader, ast.Name) and loader.id in {"SafeLoader", "CSafeLoader"}
            if not safe:
                self._add(node, Severity.HIGH, "CWE-502", "yaml.load() without SafeLoader")

        self.generic_visit(node)


@register
class AstScanner(BasePlugin):
    name = "ast-dangerous-calls"
    description = "AST scan for eval/exec, shell calls, and unsafe deserialization"
    target_type = TargetType.OFFLINE
    priority = 20

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        root = Path(target).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Path not found: {root}")

        findings: list[Finding] = []
        files = [root] if root.is_file() else root.rglob("*.py")
        for path in files:
            if not path.is_file() or path.suffix != ".py":
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError):
                continue
            rel = str(path.relative_to(root)) if root.is_dir() else path.name
            visitor = _Visitor(source, rel, target, self.name)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        return findings