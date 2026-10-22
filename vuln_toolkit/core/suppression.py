from __future__ import annotations

import fnmatch
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SUPPRESSION_NAMES = (".vulnignore", ".vulnignore.json")


def find_suppression_file(start: Path | None) -> Path | None:
    cur = (start or Path.cwd()).resolve()
    if cur.is_file():
        cur = cur.parent
    for parent in [cur, *cur.parents]:
        for name in SUPPRESSION_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None


def load_suppressions(start: Path | None) -> list[dict[str, Any]]:
    path = find_suppression_file(start)
    if not path:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not parse suppression file %s: %s", path, exc)
        return []
    rules = data.get("suppress", [])
    if rules:
        log.info("Loaded %d suppression rule(s) from %s", len(rules), path)
    return rules


def apply_suppressions(findings: list, rules: list[dict[str, Any]]) -> list:
    if not rules:
        return findings
    return [f for f in findings if not _is_suppressed(f, rules)]


def _is_suppressed(finding, rules: list[dict[str, Any]]) -> bool:
    for rule in rules:
        if "id" in rule:
            if rule["id"] == finding.id:
                return True
            continue
        if not any(k in rule for k in ("plugin", "title", "cve", "severity", "file")):
            continue
        if "plugin" in rule and rule["plugin"] != finding.plugin:
            continue
        if "title" in rule and rule["title"] != finding.title:
            continue
        if "cve" in rule and rule["cve"] != finding.cve:
            continue
        if "severity" in rule and rule["severity"] != finding.severity.value:
            continue
        if "file" in rule:
            if not finding.file or not fnmatch.fnmatch(finding.file, rule["file"]):
                continue
        return True
    return False