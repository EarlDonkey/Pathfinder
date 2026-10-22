from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from vuln_toolkit.core.plugin_base import (
    BasePlugin,
    Finding,
    SEVERITY_ORDER,
    TargetType,
    get_registry,
)

log = logging.getLogger(__name__)

BUILTIN_PLUGIN_PACKAGES = ("vuln_toolkit.plugins",)


@dataclass
class ScanResult:
    target: str
    mode: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    plugins_run: list[str] = field(default_factory=list)
    duration: float = 0.0

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])


class ScannerOrchestrator:
    def __init__(self, extra_plugin_dirs: list[str] | None = None) -> None:
        self._extra_dirs = extra_plugin_dirs or []
        self._discovered = False

    # ---------- discovery ----------
    def discover(self) -> None:
        if self._discovered:
            return
        for pkg_name in BUILTIN_PLUGIN_PACKAGES:
            self._import_package_plugins(pkg_name)
        for d in self._extra_dirs:
            self._import_directory(Path(d))
        self._import_entry_points()
        self._discovered = True
        log.debug("Discovered %d plugin(s): %s", len(get_registry()), ", ".join(sorted(get_registry())))

    def _import_package_plugins(self, pkg_name: str) -> None:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            log.warning("Plugin package not found: %s", pkg_name)
            return
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_"):
                continue
            self._safe_import(f"{pkg_name}.{info.name}")

    def _import_directory(self, directory: Path) -> None:
        if not directory.is_dir():
            log.warning("Plugin dir does not exist: %s", directory)
            return
        for py in sorted(directory.glob("*.py")):
            if py.name.startswith("_"):
                continue
            mod_name = f"vuln_ext_{py.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, py)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[mod_name] = module
                    spec.loader.exec_module(module)
            except Exception:
                log.exception("Failed to load external plugin %s", py)

    def _import_entry_points(self) -> None:
        try:
            from importlib.metadata import entry_points
        except ImportError:
            return
        try:
            eps = entry_points()
            group = eps.select(group="vuln_toolkit.plugins") if hasattr(eps, "select") else eps.get("vuln_toolkit.plugins", [])
            for ep in group:
                try:
                    ep.load()
                except Exception:
                    log.exception("Entry-point plugin failed: %s", ep)
        except Exception:
            log.debug("Entry-point discovery unavailable", exc_info=True)

    def _safe_import(self, module_name: str) -> None:
        try:
            importlib.import_module(module_name)
        except Exception:
            log.exception("Failed to import plugin module %s", module_name)

    # ---------- execution ----------
    def run(self, mode: TargetType, target: str) -> ScanResult:
        self.discover()
        result = ScanResult(target=target, mode=mode.value)
        started = time.perf_counter()

        candidates: list[type[BasePlugin]] = [
            cls for cls in get_registry().values() if cls().supports(mode)
        ]
        if not candidates:
            log.warning("No plugins support mode '%s'", mode.value)

        for cls in sorted(candidates, key=lambda c: c.name):
            plugin = cls()
            pstart = time.perf_counter()
            try:
                findings = plugin.run(target)
                result.findings.extend(findings)
                result.plugins_run.append(plugin.name)
                log.info(
                    "%-16s %3d finding(s) in %.2fs",
                    plugin.name, len(findings), time.perf_counter() - pstart,
                )
            except Exception as exc:
                log.exception("Plugin '%s' crashed", plugin.name)
                result.errors.append({"plugin": plugin.name, "error": repr(exc)})

        result.duration = time.perf_counter() - started
        return result