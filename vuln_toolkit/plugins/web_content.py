from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

TIMEOUT = 5
CONCURRENCY = 8
DELAY_BETWEEN = 0.05
UA = "vuln-toolkit/0.1"

PATHS: list[tuple[str, Severity, str]] = [
    ("/.git/HEAD",                 Severity.CRITICAL, "Git metadata exposed — clone the repo."),
    ("/.git/config",               Severity.CRITICAL, "Git config exposed."),
    ("/.svn/entries",              Severity.HIGH,     "SVN metadata exposed."),
    ("/.hg/requires",              Severity.HIGH,     "Mercurial metadata exposed."),
    ("/.env",                      Severity.CRITICAL, "Environment file — likely contains credentials."),
    ("/.env.local",                Severity.CRITICAL, "Local env file exposed."),
    ("/.env.production",           Severity.CRITICAL, "Production env file exposed."),
    ("/.aws/credentials",          Severity.CRITICAL, "AWS credentials exposed."),
    ("/.docker/config.json",       Severity.HIGH,     "Docker registry credentials exposed."),
    ("/.npmrc",                    Severity.HIGH,     "npm registry token exposed."),
    ("/.htpasswd",                 Severity.HIGH,     "htpasswd file exposed."),
    ("/.DS_Store",                 Severity.LOW,      "macOS filesystem index leaked."),
    ("/backup.zip",                Severity.HIGH,     "Backup archive downloadable."),
    ("/backup.tar.gz",             Severity.HIGH,     "Backup archive downloadable."),
    ("/backup.sql",                Severity.HIGH,     "SQL dump downloadable."),
    ("/db.sql",                    Severity.HIGH,     "SQL dump downloadable."),
    ("/dump.sql",                  Severity.HIGH,     "SQL dump downloadable."),
    ("/site.zip",                  Severity.HIGH,     "Site archive downloadable."),
    ("/www.zip",                   Severity.HIGH,     "Site archive downloadable."),
    ("/web.rar",                   Severity.HIGH,     "Site archive downloadable."),
    ("/admin",                     Severity.MEDIUM,   "Admin interface reachable."),
    ("/admin/",                    Severity.MEDIUM,   "Admin interface reachable."),
    ("/administrator",             Severity.MEDIUM,   "Admin interface reachable."),
    ("/wp-admin/",                 Severity.INFO,     "WordPress admin reachable."),
    ("/wp-login.php",              Severity.INFO,     "WordPress login reachable."),
    ("/user/login",                Severity.INFO,     "Drupal login reachable."),
    ("/administrator/index.php",   Severity.INFO,     "Joomla admin reachable."),
    ("/phpmyadmin/",               Severity.MEDIUM,   "phpMyAdmin exposed."),
    ("/pma/",                      Severity.MEDIUM,   "phpMyAdmin exposed."),
    ("/adminer.php",               Severity.MEDIUM,   "Adminer exposed."),
    ("/phpinfo.php",               Severity.HIGH,     "phpinfo() — full config disclosure."),
    ("/info.php",                  Severity.HIGH,     "phpinfo() variant."),
    ("/server-status",             Severity.MEDIUM,   "Apache mod_status exposed."),
    ("/server-info",               Severity.MEDIUM,   "Apache mod_info exposed."),
    ("/actuator",                  Severity.HIGH,     "Spring Actuator exposed."),
    ("/actuator/env",              Severity.CRITICAL, "Spring Actuator env — secrets often present."),
    ("/actuator/heapdump",         Severity.CRITICAL, "Spring Actuator heap dump."),
    ("/actuator/health",           Severity.LOW,      "Spring Actuator health."),
    ("/metrics",                   Severity.MEDIUM,   "Prometheus metrics exposed."),
    ("/debug/default",             Severity.HIGH,     "Debug endpoint exposed."),
    ("/trace",                     Severity.MEDIUM,   "Stack-trace endpoint exposed."),
    ("/console",                   Severity.HIGH,     "Admin console path."),
    ("/graphiql",                  Severity.MEDIUM,   "GraphiQL playground exposed."),
    ("/graphql",                   Severity.INFO,     "GraphQL endpoint reachable."),
    ("/wp-content/",               Severity.INFO,     "WordPress content dir."),
    ("/wp-json/wp/v2/users",       Severity.MEDIUM,   "WordPress REST user enumeration."),
    ("/sites/default/settings.php", Severity.HIGH,    "Drupal settings file."),
    ("/CHANGELOG.md",              Severity.LOW,      "CHANGELOG exposed (version hints)."),
    ("/README.md",                 Severity.LOW,      "README exposed (architecture hints)."),
    ("/package.json",              Severity.LOW,      "package.json exposed."),
    ("/composer.lock",             Severity.LOW,      "composer.lock exposed."),
    ("/yarn.lock",                 Severity.LOW,      "yarn.lock exposed."),
    ("/.github/workflows/",        Severity.LOW,      ".github workflows directory."),
    ("/.circleci/config.yml",      Severity.LOW,      "CircleCI config exposed."),
    ("/jenkins/",                  Severity.MEDIUM,   "Jenkins instance exposed."),
    ("/gitlab/",                   Severity.LOW,      "GitLab instance reachable."),
    ("/bitbucket/",                Severity.LOW,      "Bitbucket reachable."),
    ("/latest/meta-data/",         Severity.CRITICAL, "AWS metadata proxy path reachable via app."),
    ("/computeMetadata/v1/",       Severity.CRITICAL, "GCP metadata proxy path reachable via app."),
    ("/metadata/instance",         Severity.CRITICAL, "Azure metadata proxy path reachable via app."),
    ("/.well-known/openid-configuration", Severity.INFO, "OpenID Connect metadata."),
    ("/health",                    Severity.INFO,     "Health-check endpoint."),
    ("/status",                    Severity.INFO,     "Status page."),
    ("/api/",                      Severity.INFO,     "API root reachable."),
    ("/api/v1/",                   Severity.INFO,     "API v1 root reachable."),
    ("/api/v2/",                   Severity.INFO,     "API v2 root reachable."),
    ("/swagger-ui.html",           Severity.MEDIUM,   "Swagger UI exposed."),
    ("/swagger-ui/",               Severity.MEDIUM,   "Swagger UI exposed."),
    ("/openapi.json",              Severity.MEDIUM,   "OpenAPI spec exposed."),
    ("/v2/api-docs",               Severity.MEDIUM,   "Springfox API docs."),
]

NOISE_MARKERS = (
    "not found", "404", "page not found", "does not exist",
    "cannot be found", "nothing was found",
)

def _normalize(target: str) -> str | None:
    if "://" in target:
        p = urlparse(target)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return f"{p.scheme}://{p.netloc}"
    if not target or "/" in target:
        return None
    return f"http://{target}"

def _fingerprint(data: bytes) -> str:
    return hashlib.sha256(data[:2000]).hexdigest()[:16]

def _looks_like_noise(status: int, body: bytes, root_fp: str, root_status: int) -> bool:
    if status == 200:
        fp = _fingerprint(body)
        if fp == root_fp and root_status == 200:
            return True
    if status == 200 and len(body) < 500:
        low = body.lower()
        if any(m in low for m in NOISE_MARKERS):
            return True
    return False

def _fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec B310
            return r.status, r.read(60_000)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""

async def _afetch(url: str):
    return await asyncio.to_thread(_fetch, url)

@register
class WebContent(BasePlugin):
    name = "web-content"
    description = "Fuzz ~80 common sensitive paths (secrets, backups, admin, debug)"
    target_type = TargetType.ONLINE
    priority = 45

    async def _run_async(self, target: str) -> list[Finding]:
        base = _normalize(target)
        if base is None:
            return []

        # Baseline 1: Root path
        root_status, root_body = await _afetch(base)
        if root_status is None:
            return []
        root_fp = _fingerprint(root_body)

        # Baseline 2: Random nonsense path to detect catch-all 401/403s
        random_path = f"/vtk-{secrets.token_hex(6)}"
        baseline_status, _ = await _afetch(urljoin(base + "/", random_path))

        findings: list[Finding] = []
        sem = asyncio.Semaphore(CONCURRENCY)

        async def probe(path: str, sev: Severity, desc: str) -> Finding | None:
            url = urljoin(base + "/", path.lstrip("/"))
            async with sem:
                await asyncio.sleep(DELAY_BETWEEN)
                status, body = await _afetch(url)
            
            if status is None or status == 404:
                return None

            # If the server returns the SAME error code for a fake path, it's a catch-all.
            if status == baseline_status:
                return None

            # Filter out noise (soft 404s)
            if status == 200 and _looks_like_noise(status, body, root_fp, root_status):
                return None
            
            # If it's a genuine 401/403 (not catch-all), it means the path exists but is blocked.
            if status in (401, 403):
                sev = Severity.LOW if sev in (Severity.INFO, Severity.LOW) else sev

            return Finding(
                plugin=self.name,
                title=f"Exposed path: {path}",
                severity=sev,
                target=target,
                category="web-path",
                evidence=f"GET {url} -> HTTP {status}" + (f", {len(body)} bytes" if body else ""),
                description=desc,
                remediation="Remove the file, add an auth gateway, or block the path at the reverse proxy.",
            )

        results = await asyncio.gather(*(probe(p, s, d) for p, s, d in PATHS))
        findings.extend(r for r in results if r)

        return findings

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        return asyncio.run(self._run_async(target))