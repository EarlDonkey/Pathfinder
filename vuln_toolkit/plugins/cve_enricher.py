from __future__ import annotations

import json
import logging
import re
import urllib.request
from urllib.parse import quote, urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

CIRCL = "https://cve.circl.lu/api/search/{vendor}/{product}"
TIMEOUT = 12
MAX_CVES_PER_SERVICE = 8

# Banner -> (vendor, product) pairs as expected by CIRCL's search endpoint.
BANNER_RULES = [
    (re.compile(r"OpenSSH[_-]([\d.]+)", re.I),          ("openbsd",    "openssh")),
    (re.compile(r"Apache/([\d.]+)", re.I),              ("apache",     "http_server")),
    (re.compile(r"nginx/([\d.]+)", re.I),               ("nginx",      "nginx")),
    (re.compile(r"lighttpd/([\d.]+)", re.I),            ("lighttpd",   "lighttpd")),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I),       ("microsoft",  "internet_information_services")),
    (re.compile(r"vsftpd ([\d.]+)", re.I),              ("vsftpd",     "vsftpd")),
    (re.compile(r"ProFTPD ([\d.]+)", re.I),             ("proftpd",    "proftpd")),
    (re.compile(r"(\d+\.\d+\.\d+)[\w.]* MySQL", re.I),  ("mysql",      "mysql")),
    (re.compile(r"PostgreSQL ([\d.]+)", re.I),          ("postgresql", "postgresql")),
]


def _parse_banner(banner: str | None) -> tuple[str, str, str] | None:
    if not banner:
        return None
    for pattern, (vendor, product) in BANNER_RULES:
        m = pattern.search(banner)
        if m:
            return vendor, product, m.group(1)
    return None


def _normalize_response(data) -> list[dict]:
    """CIRCL has returned three shapes over the years: list, dict-wrapped, dict-keyed."""
    if data is None:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        wrapped = data.get("data")
        if isinstance(wrapped, list):
            return [d for d in wrapped if isinstance(d, dict)]
        out: list[dict] = []
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(k, str) and k.startswith("CVE-"):
                d = dict(v)
                d.setdefault("id", k)
                out.append(d)
        return out
    return []


def _fetch_cves(vendor: str, product: str) -> list[dict]:
    url = CIRCL.format(vendor=quote(vendor), product=quote(product))
    if urlparse(url).scheme != "https":
        return []
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:  # nosec B310 — scheme enforced above
            if resp.status != 200:
                return []
            return _normalize_response(json.load(resp))
    except Exception as exc:
        log.warning("CIRCL fetch failed for %s/%s: %s", vendor, product, exc)
        return []


def _cvss_of(cve: dict) -> float:
    for field in ("cvss3", "cvss"):
        v = cve.get(field)
        if isinstance(v, (int, float)):
            return float(v)
    return 0.0


def _sev_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _ver_tuple(v: str | None) -> tuple[int, ...] | None:
    if not v or not isinstance(v, str):
        return None
    m = re.match(r"^(\d+(?:\.\d+)*)", v.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cpe_versions(cve: dict) -> list[str]:
    """Extract version tokens (index 5) from CIRCL's vulnerable_configuration CPE list."""
    versions: list[str] = []
    for conf in cve.get("vulnerable_configuration") or []:
        cpe = ""
        if isinstance(conf, str):
            cpe = conf
        elif isinstance(conf, dict):
            cpe = conf.get("id") or conf.get("cpe23Uri") or ""
        if not cpe:
            continue
        parts = cpe.split(":")
        if len(parts) >= 6:
            versions.append(parts[5])
    return versions


def _version_applies(detected: str, versions: list[str]) -> bool | None:
    """True if detected matches a listed version; False if concrete versions but no match; None if unknown."""
    if not versions:
        return None
    dv = _ver_tuple(detected)
    if dv is None:
        return None
    saw_concrete = False
    for v in versions:
        if v in ("*", "-"):
            return True
        vt = _ver_tuple(v)
        if vt is None:
            continue
        saw_concrete = True
        if vt == dv:
            return True
    return False if saw_concrete else None


@register
class CVEEnricher(BasePlugin):
    name = "cve-enricher"
    description = "Map detected services to candidate CVEs via CIRCL"
    target_type = TargetType.ONLINE
    priority = 200  # runs after port_scanner (10)

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        if context is None:
            return []
        services = context.state.get("online", {}).get("services", [])
        if not services:
            log.info("cve-enricher: no services from port scanner; skipping")
            return []

        findings: list[Finding] = []
        for svc in services:
            parsed = _parse_banner(svc.get("banner"))
            if not parsed:
                continue
            vendor, product, version = parsed
            log.info("cve-enricher: %s/%s (detected %s on port %s)",
                     vendor, product, version, svc.get("port"))

            cves = _fetch_cves(vendor, product)
            cves.sort(key=_cvss_of, reverse=True)

            emitted = 0
            for cve in cves:
                if emitted >= MAX_CVES_PER_SERVICE:
                    break
                cve_id = cve.get("id") or (cve.get("cveMetadata") or {}).get("cveId")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                applies = _version_applies(version, _cpe_versions(cve))
                if applies is False:
                    # CPE list confirms this CVE does not affect the detected version.
                    continue

                score = _cvss_of(cve)
                if applies is True:
                    severity = _sev_from_cvss(score)
                    suffix = ""
                else:
                    severity = Severity.INFO
                    suffix = " [unconfirmed version applicability]"

                summary = (cve.get("summary") or "")[:400]
                findings.append(Finding(
                    plugin=self.name,
                    title=f"{vendor}/{product} {version}: {cve_id}{suffix}",
                    severity=severity,
                    target=target,
                    category="cve",
                    cve=cve_id,
                    evidence=f"{svc.get('service')} {version} on port {svc.get('port')}"
                             + (f" | CVSS={score:.1f}" if score > 0 else ""),
                    description=summary or f"Candidate CVE for {product}.",
                    remediation=(
                        f"Upgrade {product} past the affected version. "
                        f"Confirm applicability of {cve_id} to {version} "
                        f"before acting — CIRCL matches by product name."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                ))
                emitted += 1
        return findings