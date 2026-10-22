"""Bridge to existing `net/` reconnaissance package + local CVE DB matching."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from importlib.resources import files
from urllib.parse import urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

_warned: set[str] = set()

def _try_import(module_name: str):
    try:
        return __import__(module_name, fromlist=["run"])
    except ImportError as exc:
        if module_name not in _warned:
            _warned.add(module_name)
            log.debug("%s not available (%s); plugin disabled", module_name, exc)
        return None

def _extract_host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]

# ---------------------------------------------------------------------------
# Service fingerprinting (requires your external net/ package)
# ---------------------------------------------------------------------------

@register
class NetServiceFingerprint(BasePlugin):
    name = "net-service-fingerprint"
    description = "Banner-grab and identify services (requires net.service_fingerprint)"
    target_type = TargetType.ONLINE
    priority = 20

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        net_mod = _try_import("net.service_fingerprint")
        if net_mod is None:
            return []
        host = _extract_host(target)
        services = context.state.get("online", {}).get("services", []) if context else []
        ports = [s["port"] for s in services if s.get("port")]
        if not ports:
            return []

        try:
            results = asyncio.run(net_mod.fingerprint_host(host, ports))
        except Exception:
            log.exception("net.service_fingerprint failed")
            return []

        findings: list[Finding] = []
        for svc in results:
            version = svc.get("version") or ""
            title = f"{svc['service']} on {svc['port']}"
            if version:
                title += f": {version}"
            findings.append(Finding(
                plugin=self.name,
                title=title,
                severity=Severity.INFO,
                target=target,
                category="network-service",
                evidence=(svc.get("banner") or "")[:200],
                description=f"Service {svc['service']} identified on port {svc['port']}.",
                remediation="Ensure the service is patched and not exposed beyond its intended scope.",
            ))
            if context is not None:
                context.state.setdefault("services_detail", []).append(svc)
        return findings


# ---------------------------------------------------------------------------
# CVE correlation against the local cve_db.json
# ---------------------------------------------------------------------------

def _version_tuple(v: str) -> tuple:
    """Convert '2.4.52' to (2, 4, 52) for comparison."""
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(v))
    if not m:
        return (0, 0, 0)
    return tuple(int(x) if x else 0 for x in m.groups())

@register
class NetCVEMatch(BasePlugin):
    name = "net-cve-match"
    description = "Match observed service versions against local CVE database"
    target_type = TargetType.ONLINE
    priority = 210

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        if context is None:
            return []
        services = context.state.get("services_detail", [])
        if not services:
            return []

        try:
            db_path = files("vuln_toolkit.data").joinpath("cve_db.json")
            db = json.loads(db_path.read_text(encoding="utf-8"))
        except Exception as e:
            log.error("Failed to load local cve_db.json: %s", e)
            return []

        findings: list[Finding] = []
        for svc in services:
            svc_name = svc.get("service", "").lower()
            # Aliases
            if "ssh" in svc_name: svc_name = "openssh"
            elif "httpd" in svc_name: svc_name = "apache"
            elif "postgres" in svc_name: svc_name = "postgres"
            
            if svc_name not in db:
                continue

            # Extract version, e.g. "OpenSSH_8.9p1" -> "8.9"
            raw_ver = svc.get("version") or ""
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", raw_ver)
            if not m:
                continue
            
            obs_ver = _version_tuple(m.group(1))

            for rule in db[svc_name]:
                req_ver = _version_tuple(rule.get("before", ""))
                if obs_ver < req_ver:
                    for cve in rule.get("cves", []):
                        sev_map = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                        }
                        findings.append(Finding(
                            plugin=self.name,
                            title=f"{cve['id']}: {svc_name} {m.group(1)}",
                            severity=sev_map.get(cve.get("severity", "medium"), Severity.MEDIUM),
                            target=target,
                            category="cve",
                            cve=cve["id"],
                            evidence=f"port {svc.get('port')}, observed {m.group(1)} (requires < {rule.get('before')})",
                            description=cve.get("summary", ""),
                            remediation=f"Upgrade {svc_name} to version {rule.get('before')} or higher.",
                        ))
        return findings

# ---------------------------------------------------------------------------
# SNMP enumeration (requires your external net/ package)
# ---------------------------------------------------------------------------

@register
class NetSNMP(BasePlugin):
    name = "net-snmp"
    description = "SNMP walker — harvest sysDescr, interfaces, ARP cache, routing"
    target_type = TargetType.ONLINE
    priority = 15

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        snmp_mod = _try_import("net.snmp")
        if snmp_mod is None:
            return []
        host = _extract_host(target)
        try:
            result = asyncio.run(snmp_mod.walk(host))
        except Exception:
            log.exception("net.snmp.walk failed")
            return []
        if not result.get("community"):
            return []

        community = result["community"]
        system = result.get("system", {})
        is_default = community in getattr(snmp_mod, "DEFAULT_COMMUNITIES", [])

        findings: list[Finding] = []
        findings.append(Finding(
            plugin=self.name,
            title=f"SNMPv2c responds with community '{community}'"
                  + (" (well-known default)" if is_default else ""),
            severity=Severity.HIGH if is_default else Severity.MEDIUM,
            target=target,
            category="network",
            evidence=f"sysDescr: {system.get('sysDescr', '?')[:120]}",
            description=(
                "SNMP responds with a default community string. An attacker can read "
                "the full MIB, including ARP cache, routes, and interface inventory."
            ),
            remediation="Change the community string, then disable SNMPv2c entirely and use SNMPv3.",
            cwe="CWE-521",
        ))
        return findings

# ---------------------------------------------------------------------------
# mDNS / SSDP / WS-Discovery (requires your external net/ package)
# ---------------------------------------------------------------------------

@register
class NetMulticast(BasePlugin):
    name = "net-multicast"
    description = "mDNS / SSDP / WS-Discovery device discovery"
    target_type = TargetType.ONLINE
    priority = 12

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        mc_mod = _try_import("net.multicast")
        if mc_mod is None:
            return []
        try:
            devices = asyncio.run(mc_mod.discover(duration=5, fetch_descriptions=False))
        except Exception:
            log.exception("net.multicast failed")
            return []

        findings: list[Finding] = []
        for key, dev in devices.items():
            summary = dev.summary() if hasattr(dev, "summary") else key
            findings.append(Finding(
                plugin=self.name,
                title=f"Multicast device: {summary}",
                severity=Severity.INFO,
                target=target,
                category="network-device",
                evidence=f"{dev.ip} ({','.join(sorted(dev.protocols))})",
                description=f"Hostname(s): {', '.join(sorted(dev.hostnames)) or '—'}.",
                remediation="Disable mDNS/SSDP on internet-facing segments.",
            ))
        return findings

# ---------------------------------------------------------------------------
# Headless screenshots (requires your external net/ package)
# ---------------------------------------------------------------------------

@register
class NetScreenshot(BasePlugin):
    name = "net-screenshot"
    description = "Headless Chromium screenshot of the target's HTTP root"
    target_type = TargetType.ONLINE
    priority = 60

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        screenshot_mod = _try_import("net.screenshot")
        if screenshot_mod is None:
            return []
        host = _extract_host(target)
        try:
            results = asyncio.run(screenshot_mod.capture_many(
                [f"http://{host}", f"https://{host}"],
                concurrency=2, verbose=False,
            ))
        except Exception:
            log.exception("net.screenshot failed")
            return []

        ok = [r for r in results if r.get("path")]
        if not ok:
            return []
        return [Finding(
            plugin=self.name,
            title=f"Captured {len(ok)} screenshot(s)",
            severity=Severity.INFO,
            target=target,
            category="artifact",
            evidence="; ".join(r["path"] for r in ok),
            description="Screenshots saved for the report dossier.",
            remediation="Artifact — attach to the report.",
        )]