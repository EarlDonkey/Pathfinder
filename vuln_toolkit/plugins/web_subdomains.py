from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
import urllib.error
from urllib.parse import urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

def _extract_domain(target: str) -> str | None:
    if "://" in target:
        host = urlparse(target).hostname
    else:
        host = target.split("/")[0].split(":")[0]
    
    if not host:
        return None
        
    # Strip www. for broader enumeration
    if host.startswith("www."):
        return host[4:]
    return host

def _fetch_crtsh(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        log.warning("crt.sh query failed for %s: %s", domain, e)
        return set()

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        # crt.sh returns newline-separated domains in a single field
        for sub in name_value.split("\n"):
            sub = sub.strip().lower()
            if sub.endswith(domain) and "*" not in sub:
                subdomains.add(sub)
                
    return subdomains

@register
class WebSubdomains(BasePlugin):
    name = "web-subdomains"
    description = "Enumerate subdomains via Certificate Transparency logs (crt.sh)"
    target_type = TargetType.ONLINE
    priority = 5  # Run FIRST, before port scanning or web fuzzing

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        domain = _extract_domain(target)
        if not domain:
            return []

        log.info("Querying crt.sh for subdomains of %s...", domain)
        subs = _fetch_crtsh(domain)
        
        if not subs:
            return []

        findings: list[Finding] = []
        
        # We don't want to report the root domain itself as a "subdomain"
        subs.discard(domain)
        subs.discard(f"www.{domain}")

        if not subs:
            return []

        for sub in sorted(subs):
            findings.append(Finding(
                plugin=self.name,
                title=f"Subdomain discovered: {sub}",
                severity=Severity.INFO,
                target=target,
                category="asset-discovery",
                evidence=f"Found in Certificate Transparency logs",
                description=f"Discovered {sub} associated with {domain}.",
                remediation="Review if this subdomain should be publicly resolvable and scanned.",
            ))

        # Store in context so other tools (like the engine) can potentially scan them later
        if context is not None:
            context.state.setdefault("subdomains", []).extend(list(subs))

        return findings