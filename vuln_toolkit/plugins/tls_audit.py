from __future__ import annotations

import datetime
import logging
import socket
import ssl
from urllib.parse import urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

TIMEOUT = 6

# (protocol constant, human name, severity if supported, remediation note)
TLS_VERSIONS = [
    (ssl.TLSVersion.TLSv1,   "TLS 1.0", Severity.HIGH, "TLS 1.0 is deprecated (RFC 8996)."),
    (ssl.TLSVersion.TLSv1_1, "TLS 1.1", Severity.HIGH, "TLS 1.1 is deprecated (RFC 8996)."),
    (ssl.TLSVersion.TLSv1_2, "TLS 1.2", Severity.INFO, None),
    (ssl.TLSVersion.TLSv1_3, "TLS 1.3", Severity.INFO, None),
]


def _extract_host(target: str) -> str | None:
    if "://" in target:
        return urlparse(target).hostname
    host = target.split("/")[0].split(":")[0]
    return host or None


def _pick_endpoint(target: str, context: ScanContext | None) -> tuple[str, int] | None:
    """Return (host, port) if we have a TLS endpoint to probe, else None."""
    if "://" in target:
        p = urlparse(target)
        if p.scheme == "https" and p.hostname:
            return p.hostname, p.port or 443
        return None  # explicit http:// — skip TLS
    if context:
        services = context.state.get("online", {}).get("services", [])
        if any(svc.get("port") == 443 for svc in services):
            host = _extract_host(target)
            if host:
                return host, 443
    return None


def _probe_version(host: str, port: int, version) -> tuple[bool, str | None, tuple | None]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.version(), ssock.cipher()
    except (ssl.SSLError, OSError):
        return False, None, None


def _check_cert(host: str, port: int):
    """('valid', expiry_dt, None) | ('invalid', None, reason) | ('error', None, reason)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not not_after:
                    return "error", None, "no notAfter field"
                secs = ssl.cert_time_to_seconds(not_after)
                expiry = datetime.datetime.fromtimestamp(secs, tz=datetime.timezone.utc)
                return "valid", expiry, None
    except ssl.SSLCertVerificationError as e:
        return "invalid", None, (e.verify_message or str(e))
    except Exception as e:
        return "error", None, str(e)


@register
class TLSAudit(BasePlugin):
    name = "tls-audit"
    description = "Check TLS protocol versions, ciphers, and certificate validity"
    target_type = TargetType.ONLINE
    priority = 40

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        endpoint = _pick_endpoint(target, context)
        if endpoint is None:
            return []
        host, port = endpoint
        findings: list[Finding] = []

        # --- certificate ---
        status, expiry, err = _check_cert(host, port)
        if status == "invalid":
            findings.append(Finding(
                plugin=self.name,
                title="TLS certificate validation failed",
                severity=Severity.HIGH,
                target=target,
                category="tls",
                evidence=f"{host}:{port} - {err}",
                description="Certificate validation failed. Common causes: expired, self-signed, "
                            "hostname mismatch, or missing intermediate chain.",
                remediation="Renew and correctly configure the certificate; serve the full chain.",
            ))
        elif status == "valid" and expiry is not None:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            days = (expiry - now).days
            if days < 0:
                sev, note = Severity.HIGH, f"expired {abs(days)} day(s) ago"
            elif days < 14:
                sev, note = Severity.MEDIUM, f"expires in {days} day(s)"
            elif days < 30:
                sev, note = Severity.LOW, f"expires in {days} day(s)"
            else:
                sev, note = None, None
            if sev is not None:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Certificate {note}",
                    severity=sev,
                    target=target,
                    category="tls",
                    evidence=f"{host}:{port} cert expires {expiry.isoformat()}",
                    description="Certificate is close to expiry or already expired.",
                    remediation="Renew the certificate before expiry.",
                ))

        # --- protocol versions ---
        for version, name, dep_sev, note in TLS_VERSIONS:
            ok, ver_name, cipher = _probe_version(host, port, version)
            if ok and note is not None:
                cipher_name = cipher[0] if cipher else "unknown"
                findings.append(Finding(
                    plugin=self.name,
                    title=f"{name} supported",
                    severity=dep_sev,
                    target=target,
                    category="tls",
                    evidence=f"{host}:{port} negotiated {ver_name} with {cipher_name}",
                    description=note,
                    remediation=f"Disable {name} and require TLS 1.2+.",
                ))

        # --- cipher strength on TLS 1.2 ---
        ok, _ver_name, cipher = _probe_version(host, port, ssl.TLSVersion.TLSv1_2)
        if ok and cipher:
            bits = cipher[2]
            if bits and bits < 128:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Weak cipher ({bits}-bit)",
                    severity=Severity.MEDIUM,
                    target=target,
                    category="tls",
                    evidence=f"{cipher[0]} ({bits}-bit)",
                    description="Negotiated cipher uses <128-bit strength.",
                    remediation="Prefer AES-128-GCM or ChaCha20-Poly1305.",
                ))

        return findings