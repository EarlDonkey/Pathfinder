from __future__ import annotations

import asyncio
import logging
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vuln_toolkit.core.plugin_base import (
    BasePlugin, Finding, ScanContext, Severity, TargetType, register,
)

log = logging.getLogger(__name__)

TIMEOUT = 6
DELAY = 0.15
UA = "vuln-toolkit/0.1"
REDIRECT_BOUNCE = "https://vuln-toolkit-canary.example.invalid/"

SQL_ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "mysqli_fetch", "You have an error in your SQL syntax",
    "ORA-0", "ORA-1", "PostgreSQL", "PG::SyntaxError", "unterminated quoted string",
    "SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
    "Incorrect syntax near", "Microsoft OLE DB Provider for SQL Server",
    "Division by zero in", "Unknown column", "syntax error at or near",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "returnUrl", "return_to",
    "next", "url", "goto", "to", "target", "dest", "destination", "redir",
    "continue", "forward", "link", "out", "view", "callback", "callbackUrl",
]

MAX_PARAMS_PER_URL = 8


def _normalize(target: str) -> str | None:
    if "://" in target:
        p = urlparse(target)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return target
    if not target or "/" in target:
        return None
    return f"http://{target}"


def _with_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _fetch(url: str, follow_redirects: bool = True):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    handlers = [urllib.request.HTTPRedirectHandler()] if follow_redirects else [NoRedirect]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:  # nosec B310 — authorized target
            return r.status, dict(r.headers), r.read(300_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""
    except Exception:
        return None, {}, b""


async def _afetch(url: str, follow_redirects: bool = True):
    return await asyncio.to_thread(_fetch, url, follow_redirects)


@register
class WebInjection(BasePlugin):
    name = "web-injection"
    description = "Reflected XSS, error-based SQLi, and open-redirect probes"
    target_type = TargetType.ONLINE
    priority = 50

    async def _run_async(self, target: str) -> list[Finding]:
        base = _normalize(target)
        if base is None:
            return []

        status, headers, body = await _afetch(base)
        if status is None:
            return []

        parsed = urlparse(base)
        findings: list[Finding] = []

        # Collect candidate params: from URL, plus a fixed set we test on
        # every page (open-redirect params).
        url_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]

        # --- 1. Reflected XSS via URL params ---
        for param in url_params[:MAX_PARAMS_PER_URL]:
            await asyncio.sleep(DELAY)
            marker = f"vtk{secrets.token_hex(4)}"
            payload = f"<{marker}>\"'"
            probe_url = _with_param(base, param, payload)
            st, _, pbody = await _afetch(probe_url)
            if st is None:
                continue
            text = pbody.decode("utf-8", "ignore")
            if payload in text:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Reflected XSS candidate: parameter '{param}'",
                    severity=Severity.HIGH,
                    target=target,
                    category="web-xss",
                    evidence=f"GET {probe_url} reflected '{payload}' verbatim",
                    description=(
                        f"Parameter '{param}' echoes raw HTML metacharacters back "
                        f"to the client. Investigate whether output encoding is applied "
                        f"at the point of HTML rendering; if not, this is a reflected XSS."
                    ),
                    remediation=(
                        "HTML-encode user input on output "
                        "(or use a templating engine with auto-escaping). "
                        "Add a CSP to limit exploitation of any missed spots."
                    ),
                    cwe="CWE-79",
                ))
            elif f"&lt;{marker}&gt;" in text or f"&#x3C;{marker}&#x3E;".lower() in text.lower():
                # properly escaped — good, no finding
                pass

        # --- 2. Error-based SQLi via quote injection ---
        for param in url_params[:MAX_PARAMS_PER_URL]:
            await asyncio.sleep(DELAY)
            for probe_val in ("'", "''", "\"", "1' AND '1'='2"):
                probe_url = _with_param(base, param, probe_val)
                st, _, pbody = await _afetch(probe_url)
                if st is None:
                    continue
                text = pbody.decode("utf-8", "ignore")
                matched = next((sig for sig in SQL_ERROR_SIGNATURES if sig in text), None)
                if matched:
                    findings.append(Finding(
                        plugin=self.name,
                        title=f"SQL error on parameter '{param}'",
                        severity=Severity.HIGH,
                        target=target,
                        category="web-sqli",
                        evidence=f"GET {probe_url} matched SQL error signature: {matched!r}",
                        description=(
                            f"Injecting {probe_val!r} into parameter '{param}' triggered "
                            f"a database error. This is a strong signal of an unfiltered "
                            f"SQL injection (may require blind/timing confirmation)."
                        ),
                        remediation=(
                            "Use parameterized queries or an ORM. "
                            "Never concatenate user input into SQL strings. "
                            "Suppress DB error detail in production responses."
                        ),
                        cwe="CWE-89",
                    ))
                    break

        # --- 3. Open redirect ---
        candidates = set(REDIRECT_PARAMS) | set(url_params)
        for param in sorted(candidates):
            await asyncio.sleep(DELAY)
            probe_url = _with_param(base, param, REDIRECT_BOUNCE)
            st, hdrs, _ = await _afetch(probe_url, follow_redirects=False)
            if st is None or st not in (301, 302, 303, 307, 308):
                continue
            loc = ""
            for k, v in hdrs.items():
                if k.lower() == "location":
                    loc = v
                    break
            if REDIRECT_BOUNCE in loc:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Open redirect: parameter '{param}'",
                    severity=Severity.MEDIUM,
                    target=target,
                    category="web-redirect",
                    evidence=f"GET {probe_url} -> {st} Location: {loc}",
                    description=(
                        f"Parameter '{param}' is reflected into the Location header "
                        f"without validation. Can be abused for phishing and OAuth token theft."
                    ),
                    remediation=(
                        "Validate the destination against an allow-list of relative "
                        "paths or trusted hostnames before redirecting."
                    ),
                    cwe="CWE-601",
                ))

        return findings

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        return asyncio.run(self._run_async(target))