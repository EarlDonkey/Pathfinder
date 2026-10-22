from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from vuln_toolkit.core.plugin_base import BasePlugin, Finding, Severity, TargetType, register

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
                995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
RISKY = {
    21:   "FTP transmits credentials in cleartext; prefer SFTP/FTPS.",
    23:   "Telnet is cleartext; replace with SSH.",
    445:  "SMB should not be internet-exposed.",
    3306: "MySQL exposed externally; restrict to trusted networks.",
    5432: "PostgreSQL exposed externally; restrict to trusted networks.",
    6379: "Redis exposed; ensure auth + bind to localhost/firewall.",
    9200: "Elasticsearch exposed; often unauthenticated by default.",
    27017: "MongoDB exposed; ensure auth is enabled.",
}
TIMEOUT = 1.5


def _extract_host(target: str) -> str:
    if "://" in target:
        host = urlparse(target).hostname
    else:
        host = target.split("/")[0].split(":")[0]
    if not host:
        raise ValueError(f"Could not extract host from target: {target!r}")
    return host


async def _probe(host: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool]:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True
        except Exception:
            return port, False


@register
class PortScanner(BasePlugin):
    name = "tcp-ports-basic"
    description = "Async TCP connect scan of common ports"
    target_type = TargetType.ONLINE

    async def _scan(self, host: str) -> list[int]:
        sem = asyncio.Semaphore(100)
        results = await asyncio.gather(*(_probe(host, p, sem) for p in COMMON_PORTS))
        return sorted(p for p, is_open in results if is_open)

    def run(self, target: str) -> list[Finding]:
        host = _extract_host(target)
        open_ports = asyncio.run(self._scan(host))

        findings: list[Finding] = []
        for port in open_ports:
            risky = port in RISKY
            findings.append(Finding(
                plugin=self.name,
                title=f"Open TCP port {port}",
                severity=Severity.MEDIUM if risky else Severity.INFO,
                target=target,
                category="network",
                evidence=f"{host}:{port} accepted a TCP connection",
                description=RISKY.get(port, "Port is reachable from the scanning host."),
                remediation="Close the port or restrict access with a firewall if not required.",
            ))
        return findings