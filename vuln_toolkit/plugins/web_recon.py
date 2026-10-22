from __future__ import annotations

import asyncio
import logging
import re
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

TIMEOUT = 6
UA = "vuln-toolkit/0.1 (+https://example.invalid)"

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Add HSTS: max-age=31536000; includeSubDomains; preload.",
        "CWE-319",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Add a CSP with at least default-src 'self' and no unsafe-inline.",
        "CWE-1021",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Set X-Content-Type-Options: nosniff.",
        "CWE-116",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "Set X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors).",
        "CWE-1021",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
        "CWE-200",
    ),
    "Permissions-Policy": (
        Severity.LOW,
        "Set Permissions-Policy to disable powerful APIs you don't use.",
        "CWE-693",
    ),
    "Cross-Origin-Opener-Policy": (
        Severity.LOW,
        "Set Cross-Origin-Opener-Policy: same-origin.",
        "CWE-1021",
    ),
}

TECH_SIGNATURES = [
    # header name, pattern, tech name
    ("server",        re.compile(r"nginx/?([\d.]*)", re.I),          "nginx"),
    ("server",        re.compile(r"apache/?([\d.]*)", re.I),         "Apache HTTP Server"),
    ("server",        re.compile(r"microsoft-iis/?([\d.]*)", re.I),  "Microsoft IIS"),
    ("server",        re.compile(r"openresty/?([\d.]*)", re.I),      "OpenResty"),
    ("server",        re.compile(r"cloudflare", re.I),               "Cloudflare"),
    ("x-powered-by",  re.compile(r"php/?([\d.]*)", re.I),            "PHP"),
    ("x-powered-by",  re.compile(r"asp\.net", re.I),                 "ASP.NET"),
    ("x-powered-by",  re.compile(r"express", re.I),                  "Express"),
    ("x-aspnet-version", re.compile(r"([\d.]+)"),                    "ASP.NET"),
    ("x-generator",   re.compile(r"wordpress ([\d.]+)", re.I),       "WordPress"),
    ("x-generator",   re.compile(r"drupal ([\d.]+)", re.I),          "Drupal"),
    ("x-generator",   re.compile(r"joomla!? ([\d.]+)", re.I),        "Joomla"),
    ("x-drupal-cache", re.compile(r".*"),                            "Drupal"),
    ("x-drupal-dynamic-cache", re.compile(r".*"),                    "Drupal"),
    ("x-varnish",     re.compile(r".*"),                             "Varnish"),
]

COOKIE_FLAG_CHECKS = [
    ("HttpOnly", "Cookie is script-readable; XSS can steal the session.", "CWE-1004"),
    ("Secure",   "Cookie will be sent over plaintext HTTP.",             "CWE-614"),
    ("SameSite", "Cookie lacks SameSite; CSRF exposure.",                "CWE-1275"),
]

WELL_KNOWN = [
    ("/robots.txt",             Severity.INFO,   "robots.txt present; inspect for hidden paths."),
    ("/sitemap.xml",            Severity.INFO,   "sitemap.xml present."),
    ("/.well-known/security.txt", Severity.INFO, "security.txt present (good signal)."),
    ("/.well-known/change-password", Severity.INFO, "change-password spec present."),
]

# Paths that should NEVER be publicly reachable — same list as web_content
# but only the top-ten "critical disclose" signals live here so web-recon
# can stand alone on a single root fetch.
QUICK_DISCLOSURES = [
    ("/.git/HEAD",       Severity.CRITICAL, "Git repository metadata accessible."),
    ("/.env",            Severity.CRITICAL, "Environment file exposed."),
    ("/server-status",   Severity.HIGH,     "Apache mod_status exposed."),
    ("/actuator/env",    Severity.HIGH,     "Spring Actuator env exposed."),
    ("/debug/default",   Severity.MEDIUM,   "Debug endpoint exposed."),
]


def _normalize(target: str) -> str | None:
    """Return https:// if we're scanning a real URL, else build http://host."""
    if "://" in target:
        p = urlparse(target)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return f"{p.scheme}://{p.netloc}"
    if not target or "/" in target:
        return None
    return f"http://{target}"


def _fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec B310 — user-authorized target
            return r.status, dict(r.headers), r.read(300_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""
    except Exception:
        return None


async def _afetch(url):
    return await asyncio.to_thread(_fetch, url)


def _check_cookie(value: str, header_key: str):
    out = []
    low = value.lower()
    parts = [p.strip() for p in value.split(";")]
    cookie_name = parts[0].split("=", 1)[0] if parts else "?"
    for flag, description, cwe in COOKIE_FLAG_CHECKS:
        if flag.lower() not in low:
            out.append((flag, cookie_name, description, cwe))
    return out


def _tech_hits(headers: dict, body: bytes) -> list[tuple[str, str, str]]:
    hits = []
    low_headers = {k.lower(): v for k, v in headers.items()}
    for header_name, pattern, tech in TECH_SIGNATURES:
        if header_name not in low_headers:
            continue
        val = low_headers[header_name]
        m = pattern.search(val)
        if m:
            version = m.group(1) if m.groups() and m.group(1) else ""
            hits.append((tech, version, f"{header_name}: {val}"))
    text = body[:50_000].decode("utf-8", "ignore")
    for marker, tech in [
        ("wp-content/",       "WordPress"),
        ("wp-includes/",      "WordPress"),
        ("/sites/default/files", "Drupal"),
        ("/media/system/js/", "Joomla"),
        ("__NEXT_DATA__",     "Next.js"),
        ("data-reactroot",    "React"),
        ("ng-version=",       "Angular"),
        ("__vite__",          "Vite"),
    ]:
        if marker in text:
            hits.append((tech, "", f"body contains '{marker}'"))
    return hits


@register
class WebRecon(BasePlugin):
    name = "web-recon"
    description = "Security headers, cookies, CORS, tech stack, robots, well-known paths"
    target_type = TargetType.ONLINE
    priority = 35

    async def _run_async(self, target: str) -> list[Finding]:
        base = _normalize(target)
        if base is None:
            return []
        findings: list[Finding] = []

        root = await _afetch(base)
        if root is None:
            log.info("web-recon: no response from %s", base)
            return findings

        status, headers, body = root
        low = {k.lower(): v for k, v in headers.items()}

        # --- security headers ---
        for header, (sev, fix, cwe) in SECURITY_HEADERS.items():
            if header.lower() not in low:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Missing security header: {header}",
                    severity=sev,
                    target=target,
                    category="web-headers",
                    evidence=f"GET {base} -> HTTP {status}; '{header}' absent",
                    description=f"Response does not set '{header}'.",
                    remediation=fix,
                    cwe=cwe,
                ))

        # --- cookies ---
        cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]
        for value in cookie_headers:
            for flag, cookie_name, desc, cwe in _check_cookie(value, ""):
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Cookie '{cookie_name}' missing '{flag}'",
                    severity=Severity.MEDIUM if flag in ("HttpOnly", "Secure") else Severity.LOW,
                    target=target,
                    category="web-cookies",
                    evidence=value[:160],
                    description=desc,
                    remediation=f"Set the '{flag}' attribute on cookie '{cookie_name}'.",
                    cwe=cwe,
                ))

        # --- CORS ---
        acao = low.get("access-control-allow-origin", "")
        acac = low.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(Finding(
                plugin=self.name,
                title="CORS wildcard with credentials",
                severity=Severity.HIGH,
                target=target,
                category="web-cors",
                evidence=f"Access-Control-Allow-Origin: * + Credentials: true",
                description="Any origin can send credentialed requests; browser normally blocks this combo, but some frameworks allow it and other clients won't.",
                remediation="Never combine '*' with Credentials: true. Echo a fixed allow-list of origins instead.",
                cwe="CWE-942",
            ))
        elif acao == "*":
            findings.append(Finding(
                plugin=self.name,
                title="CORS wildcard origin",
                severity=Severity.LOW,
                target=target,
                category="web-cors",
                evidence="Access-Control-Allow-Origin: *",
                description="Any origin can read unauthenticated cross-origin responses.",
                remediation="Restrict to known origins unless the endpoint is truly public data.",
                cwe="CWE-942",
            ))

        # --- tech disclosure ---
        for tech, version, evidence in _tech_hits(headers, body):
            title = f"Technology disclosed: {tech}"
            if version:
                title += f" {version}"
            findings.append(Finding(
                plugin=self.name,
                title=title,
                severity=Severity.INFO if not version else Severity.LOW,
                target=target,
                category="web-fingerprint",
                evidence=evidence[:160],
                description=f"{tech} fingerprint visible in headers or body.",
                remediation=f"Suppress the identifying header or obfuscate the marker.",
            ))

        # --- robots / sitemap / well-known ---
        async def probe(path: str, sev: Severity, desc: str) -> Finding | None:
            url = urljoin(base + "/", path.lstrip("/"))
            res = await _afetch(url)
            if res is None:
                return None
            st, _, _ = res
            if st == 200:
                return Finding(
                    plugin=self.name,
                    title=f"Present: {path}",
                    severity=sev,
                    target=target,
                    category="web-wellknown",
                    evidence=f"GET {url} -> HTTP 200",
                    description=desc,
                    remediation="Remove or restrict access if it discloses internal structure.",
                )
            return None

        results = await asyncio.gather(
            *(probe(p, s, d) for p, s, d in WELL_KNOWN + QUICK_DISCLOSURES)
        )
        findings.extend(r for r in results if r)

        return findings

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        return asyncio.run(self._run_async(target))