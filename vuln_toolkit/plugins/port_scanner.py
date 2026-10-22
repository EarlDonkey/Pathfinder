from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
                995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                9200, 27017]

PORT_INFO = {
    21:    (Severity.MEDIUM, "FTP", "FTP transmits credentials in cleartext. Prefer SFTP or FTPS."),
    22:    (Severity.INFO,   "SSH", "SSH reachable. Confirm key-based auth, disable password auth, enforce rate-limiting."),
    23:    (Severity.MEDIUM, "Telnet", "Telnet is cleartext. Replace with SSH."),
    25:    (Severity.INFO,   "SMTP", "SMTP reachable. Verify relay restrictions, STARTTLS, and SPF/DKIM/DMARC."),
    53:    (Severity.INFO,   "DNS", "DNS reachable. Ensure recursion is disabled for external clients."),
    80:    (Severity.INFO,   "HTTP", "HTTP reachable. Confirm 301 redirect to HTTPS and HSTS headers."),
    110:   (Severity.MEDIUM, "POP3", "POP3 in cleartext. Use POP3S or STARTTLS."),
    143:   (Severity.MEDIUM, "IMAP", "IMAP in cleartext. Use IMAPS or STARTTLS."),
    443:   (Severity.INFO,   "HTTPS", "HTTPS reachable. Verify TLS 1.2+, modern cipher suite, and valid certificate."),
    445:   (Severity.MEDIUM, "SMB", "SMB should not be internet-exposed. Block at the perimeter."),
    1433:  (Severity.MEDIUM, "MSSQL", "MSSQL exposed. Restrict to trusted networks."),
    3306:  (Severity.MEDIUM, "MySQL", "MySQL exposed. Restrict to trusted networks."),
    3389:  (Severity.MEDIUM, "RDP", "RDP exposed. Enforce NLA, MFA, and IP allowlisting."),
    5432:  (Severity.MEDIUM, "PostgreSQL", "PostgreSQL exposed. Restrict to trusted networks."),
    5900:  (Severity.MEDIUM, "VNC", "VNC exposed. Tunnel via SSH/VPN and set a strong password."),
    6379:  (Severity.HIGH,   "Redis", "Redis exposed. Enable AUTH, bind to loopback, and firewall."),
    9200:  (Severity.HIGH,   "Elasticsearch", "Elasticsearch exposed. Often unauthenticated by default; add auth + firewall."),
    27017: (Severity.HIGH,   "MongoDB", "MongoDB exposed. Enable auth and restrict network access."),
}

# TLS-terminating ports are excluded — banner grab would need a TLS handshake first.
BANNER_PORTS = {21, 22, 25, 80, 110, 143, 8080}
TIMEOUT = 1.5


def _extract_host(target: str) -> str:
    if "://" in target:
        host = urlparse(target).hostname
    else:
        host = target.split("/")[0].split(":")[0]
    if not host:
        raise ValueError(f"Could not extract host from target: {target!r}")
    return host


async def _probe(host: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool, str | None]:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TIMEOUT
            )
            banner = None
            if port in BANNER_PORTS:
                try:
                    if port in (80, 8080):
                        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                        await writer.drain()
                    data = await asyncio.wait_for(reader.read(256), timeout=TIMEOUT)
                    if data:
                        line = data.decode("utf-8", "ignore").strip().splitlines()[0]
                        banner = line[:120]
                except Exception:  # nosec B110 — banner grab is opportunistic
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # nosec B110 — close is best-effort
                pass
            return port, True, banner
        except Exception:
            return port, False, None


@register
class PortScanner(BasePlugin):
    name = "tcp-ports-basic"
    description = "Async TCP connect scan of common ports (with banner grab)"
    target_type = TargetType.ONLINE
    priority = 10

    async def _scan(self, host: str):
        sem = asyncio.Semaphore(100)
        return await asyncio.gather(*(_probe(host, p, sem) for p in COMMON_PORTS))

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        host = _extract_host(target)
        results = asyncio.run(self._scan(host))

        findings: list[Finding] = []
        services: list[dict] = []
        for port, is_open, banner in results:
            if not is_open:
                continue
            sev, label, remediation = PORT_INFO.get(
                port,
                (Severity.INFO, f"TCP/{port}", "Verify this service is intended to be exposed."),
            )
            findings.append(Finding(
                plugin=self.name,
                title=f"Open {label} port {port}",
                severity=sev,
                target=target,
                category="network",
                evidence=f"{host}:{port}" + (f" - {banner}" if banner else ""),
                description=f"Port {port} ({label}) is reachable from the scanning host."
                            + (f" Banner: {banner}" if banner else ""),
                remediation=remediation,
            ))
            services.append({"port": port, "service": label, "banner": banner})

        if context is not None:
            context.state.setdefault("online", {})["services"] = services

        return findings