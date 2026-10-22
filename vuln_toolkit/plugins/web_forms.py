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
UA = "vuln-toolkit/0.1"

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.I)
INPUT_RE = re.compile(r"<input\b([^>]*)>", re.I)
TEXTAREA_RE = re.compile(r"<textarea\b([^>]*)>", re.I)

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "csrf_token", "csrfmiddlewaretoken", "_token",
    "_csrf", "authenticity_token", "__requestverificationtoken",
    "antiforgery", "xsrf", "x-xsrf-token",
}


def _normalize(target: str) -> str | None:
    if "://" in target:
        p = urlparse(target)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return target
    if not target or "/" in target:
        return None
    return f"http://{target}"


def _fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec B310 — authorized target
            return r.status, r.read(300_000)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""


async def _afetch(url: str):
    return await asyncio.to_thread(_fetch, url)


def _attr(attrs: str, name: str) -> str:
    for k, v in ATTR_RE.findall(attrs):
        if k.lower() == name.lower():
            return v
    return ""


def _analyze_form(base_url: str, form_attrs: str, form_body: str) -> list[tuple[str, str, Severity, str]]:
    """Return [(title, evidence, severity, cwe), ...] for one form."""
    out = []
    action = _attr(form_attrs, "action")
    method = (_attr(form_attrs, "method") or "get").lower()
    action_url = urljoin(base_url, action) if action else base_url
    page_is_https = urlparse(base_url).scheme == "https"
    action_is_https = urlparse(action_url).scheme == "https"

    inputs = INPUT_RE.findall(form_body)
    textareas = TEXTAREA_RE.findall(form_body)

    has_password = any(_attr(a, "type").lower() == "password" for a in inputs)
    has_token = False
    input_names = []
    for a in inputs:
        n = _attr(a, "name").lower()
        t = _attr(a, "type").lower()
        if n:
            input_names.append(n)
        if n in CSRF_TOKEN_NAMES or (n and "csrf" in n):
            has_token = True
        if t == "hidden" and n in CSRF_TOKEN_NAMES:
            has_token = True

    # --- Rule: POST-from-HTTPS to HTTP ---
    if page_is_https and not action_is_https and action_url.startswith("http://"):
        out.append((
            "Form posts to plaintext HTTP from an HTTPS page",
            f"action={action_url}",
            Severity.HIGH,
            "CWE-319",
        ))

    # --- Rule: login form over GET ---
    if has_password and method == "get":
        out.append((
            "Login form uses GET method",
            f"method=GET, action={action_url}",
            Severity.MEDIUM,
            "CWE-598",
        ))

    # --- Rule: login form missing CSRF token ---
    if has_password and not has_token:
        out.append((
            "Login form lacks a visible CSRF token",
            f"inputs: {', '.join(input_names[:10]) or '(none named)'}",
            Severity.MEDIUM,
            "CWE-352",
        ))

    # --- Rule: password input without autocomplete=off/new-password ---
    for a in inputs:
        if _attr(a, "type").lower() != "password":
            continue
        ac = _attr(a, "autocomplete").lower()
        if ac not in ("off", "new-password", "current-password"):
            out.append((
                "Password input missing autocomplete directive",
                f"input name='{_attr(a, 'name')}' autocomplete='{ac or '(unset)'}'",
                Severity.LOW,
                "CWE-522",
            ))
            break

    return out


@register
class WebForms(BasePlugin):
    name = "web-forms"
    description = "Audit HTML forms for CSRF tokens, GET logins, HTTP-posts-from-HTTPS"
    target_type = TargetType.ONLINE
    priority = 40

    async def _run_async(self, target: str) -> list[Finding]:
        base = _normalize(target)
        if base is None:
            return []
        status, body = await _afetch(base)
        if status is None:
            return []
        text = body.decode("utf-8", "ignore")

        findings: list[Finding] = []
        for i, m in enumerate(FORM_RE.finditer(text)):
            attrs, inner = m.group(1), m.group(2)
            for title, evidence, sev, cwe in _analyze_form(base, attrs, inner):
                findings.append(Finding(
                    plugin=self.name,
                    title=title,
                    severity=sev,
                    target=target,
                    category="web-forms",
                    evidence=evidence[:200],
                    description=f"Form #{i+1} on {base}.",
                    remediation=(
                        "Use POST for logins with a CSRF token. "
                        "Serve from HTTPS only. Add autocomplete='new-password' "
                        "or 'current-password' to password fields."
                    ),
                    cwe=cwe,
                ))
        return findings

    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        return asyncio.run(self._run_async(target))