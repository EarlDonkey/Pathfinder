from __future__ import annotations

import json
import logging
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "vuln-toolkit"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TTL_SECONDS = 86400  # 1 day


def _cache_fresh(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < TTL_SECONDS


def _safe_urlopen(url: str, timeout: int = 15):
    """Refuse non-https URLs, then delegate to urllib. Centralised nosec for B310."""
    if urlparse(url).scheme != "https":
        raise ValueError(f"Refusing non-https URL: {url}")
    return urllib.request.urlopen(url, timeout=timeout)  # nosec B310 — scheme enforced above


class KEVCatalog:
    def __init__(self, cache_dir: Path = CACHE_DIR) -> None:
        self.cache_dir = cache_dir
        self.cache_file = cache_dir / "kev.json"
        self._set: set[str] | None = None

    def fetch(self) -> set[str]:
        if self._set is not None:
            return self._set
        if _cache_fresh(self.cache_file):
            try:
                self._set = set(json.loads(self.cache_file.read_text()))
                return self._set
            except Exception:  # nosec B110 — cache corruption self-heals below
                pass
        try:
            log.info("Downloading CISA KEV catalog...")
            with _safe_urlopen(KEV_URL) as resp:
                data = json.load(resp)
            self._set = {v["cveID"] for v in data.get("vulnerabilities", [])}
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(sorted(self._set)))
            log.info("CISA KEV: %d entries cached", len(self._set))
        except Exception as exc:
            log.warning("KEV fetch failed (%s); continuing with empty set", exc)
            self._set = set()
        return self._set


class EPSSClient:
    def __init__(self, cache_dir: Path = CACHE_DIR) -> None:
        self.cache_dir = cache_dir
        self.cache_file = cache_dir / "epss.json"
        self._map: dict[str, dict | None] | None = None

    def fetch(self, cves: set[str]) -> dict[str, dict]:
        if not cves:
            return {}
        if self._map is None:
            self._map = self._load_cache()

        missing = [c for c in cves if c not in self._map]
        for start in range(0, len(missing), 100):
            self._fetch_chunk(missing[start:start + 100])
        self._save_cache()
        return {c: self._map[c] for c in cves if self._map.get(c)}

    def _fetch_chunk(self, cves: list[str]) -> None:
        if not cves:
            return
        url = f"{EPSS_URL}?cve={','.join(cves)}"
        try:
            with _safe_urlopen(url) as resp:
                data = json.load(resp)
            for row in data.get("data", []):
                cve = row.get("cve")
                if cve:
                    self._map[cve] = {
                        "epss": float(row.get("epss", 0.0)),
                        "percentile": float(row.get("percentile", 0.0)),
                    }
        except Exception as exc:
            log.warning("EPSS fetch failed for %d CVEs (%s)", len(cves), exc)
            for c in cves:
                self._map.setdefault(c, None)  # memo negative result

    def _load_cache(self) -> dict[str, dict | None]:
        if not _cache_fresh(self.cache_file):
            return {}
        try:
            return json.loads(self.cache_file.read_text())
        except Exception:  # nosec B110 — cache corruption self-heals on next save
            return {}

    def _save_cache(self) -> None:
        if self._map is None:
            return
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            clean = {k: v for k, v in self._map.items() if v is not None}
            self.cache_file.write_text(json.dumps(clean))
        except Exception:  # nosec B110 — best-effort persistence
            pass


def enrich_findings(findings: list, cache_dir: Path = CACHE_DIR) -> None:
    """Mutate findings: populate kev/epss fields and escalate severity accordingly."""
    cves = {f.cve for f in findings if f.cve and f.cve.startswith("CVE-")}
    if not cves:
        return
    kev_set = KEVCatalog(cache_dir).fetch()
    epss_map = EPSSClient(cache_dir).fetch(cves)
    for f in findings:
        if not f.cve or not f.cve.startswith("CVE-"):
            continue
        f.kev = f.cve in kev_set
        stats = epss_map.get(f.cve) or {}
        if stats:
            f.epss_score = stats.get("epss")
            f.epss_percentile = stats.get("percentile")
        _escalate(f)


def _escalate(f) -> None:
    from vuln_toolkit.core.plugin_base import Severity
    if f.kev:
        f.severity = Severity.CRITICAL
    elif f.epss_score is not None and f.epss_score >= 0.5:
        if f.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM):
            f.severity = Severity.HIGH