from __future__ import annotations

import html as _html
import json
import os
import sys
from collections import Counter
from pathlib import Path

from vuln_toolkit.core.engine import ScanResult
from vuln_toolkit.core.plugin_base import Severity, SEVERITY_ORDER

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;37m",
}
_RESET = "\033[0m"

_SEV_CLASS = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

_ANSI_OK: bool | None = None


def _enable_vt_windows() -> bool:
    """Enable ANSI processing on modern Windows consoles. Returns True if supported."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        ))
    except Exception:
        return False


def _use_color() -> bool:
    global _ANSI_OK
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    if not sys.stdout.isatty():
        return False
    if _ANSI_OK is None:
        _ANSI_OK = _enable_vt_windows()
    return _ANSI_OK


def render_console(result: ScanResult) -> str:
    color = _use_color()
    findings = result.sorted_findings()
    counts = Counter(f.severity for f in findings)
    lines: list[str] = []
    lines.append("=" * 68)
    lines.append(f"Target : {result.target}")
    lines.append(f"Mode   : {result.mode}")
    lines.append(
        f"Time   : {result.duration:.2f}s | Plugins: {len(result.plugins_run)} | "
        f"Errors: {len(result.errors)} | Suppressed: {result.suppressed}"
    )
    summary = ", ".join(f"{s.value}={counts.get(s, 0)}" for s in reversed(list(Severity)))
    lines.append(f"Results: {len(findings)} finding(s) ({summary})")
    lines.append("=" * 68)

    for f in findings:
        tag = f"[{f.severity.value.upper():^8}]"
        if color:
            tag = f"{_COLORS[f.severity]}{tag}{_RESET}"
        loc = ""
        if f.file:
            loc = f" {f.file}" + (f":{f.line}" if f.line else "")
        elif f.line:
            loc = f" line {f.line}"
        lines.append(f"{tag} {f.title}{loc}")
        if f.id:
            lines.append(f"           id: {f.id}")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence}")
        if f.cve:
            extras = [f.cve]
            if f.kev:
                extras.append("CISA KEV — actively exploited")
            if f.epss_score is not None:
                extras.append(f"EPSS={f.epss_score:.3f} ({f.epss_percentile:.0%} percentile)")
            lines.append(f"           risk: {' | '.join(extras)}")
        if f.remediation:
            lines.append(f"           fix: {f.remediation}")
        lines.append("")

    for err in result.errors:
        lines.append(f"[ ERROR  ] {err['plugin']}: {err['error']}")

    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ScanResult) -> str:
    payload = {
        "scan": {
            "target": result.target,
            "mode": result.mode,
            "duration_seconds": round(result.duration, 4),
            "plugins_run": result.plugins_run,
            "errors": result.errors,
            "suppressed": result.suppressed,
        },
        "summary": {
            sev.value: sum(1 for f in result.findings if f.severity == sev)
            for sev in Severity
        },
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }
    return json.dumps(payload, indent=2)


def render_html(result: ScanResult) -> str:
    e = _html.escape
    findings = result.sorted_findings()
    counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}

    by_cat: dict[str, list] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    CATEGORY_LABELS = {
        "web-headers":   "Security Headers",
        "web-cookies":   "Cookie Configuration",
        "web-cors":      "CORS Policy",
        "web-fingerprint": "Technology Disclosure",
        "web-wellknown": "Well-Known Paths",
        "web-path":      "Sensitive Paths",
        "web-injection": "Injection (XSS / SQLi / Redirect)",
        "web-xss":       "Reflected XSS",
        "web-sqli":      "SQL Injection",
        "web-redirect":  "Open Redirect",
        "web-forms":     "Form Security",
        "network":       "Network Services",
        "network-service": "Service Inventory",
        "network-device": "Multicast Devices",
        "cve":           "CVE Candidates",
        "sast":          "SAST Findings",
        "secret":        "Secrets in Source",
        "dependency":    "Dependency Vulnerabilities",
        "artifact":      "Artifacts",
        "general":       "Other",
    }

    sections = []
    for cat in sorted(by_cat, key=lambda c: -max(
            SEVERITY_ORDER[f.severity] for f in by_cat[c])):
        label = CATEGORY_LABELS.get(cat, cat.replace("_", " ").title())
        cards = []
        for f in by_cat[cat]:
            rows = []
            if f.file:
                rows.append(("File", f"{e(f.file)}{':' + str(f.line) if f.line else ''}"))
            if f.evidence:
                rows.append(("Evidence", f"<code>{e(f.evidence)}</code>"))
            if f.cve:
                kev = ' <span class="kev">CISA KEV</span>' if f.kev else ""
                rows.append(("CVE", f'<a href="https://nvd.nist.gov/vuln/detail/{e(f.cve)}" target="_blank" rel="noopener">{e(f.cve)}</a>{kev}'))
            if f.epss_score is not None:
                rows.append(("EPSS", f"{f.epss_score:.3f} ({f.epss_percentile:.0%})"))
            if f.cwe:
                rows.append(("CWE", e(f.cwe)))
            if f.description:
                rows.append(("Detail", e(f.description)))
            if f.remediation:
                rows.append(("Fix", e(f.remediation)))
            rows_html = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)

            cards.append(f"""
            <article class="finding {_SEV_CLASS[f.severity]}">
              <header>
                <span class="sev">{f.severity.value.upper()}</span>
                <h3>{e(f.title)}</h3>
                <span class="plugin">{e(f.plugin)}</span>
              </header>
              <table>{rows_html}</table>
            </article>""")
        sections.append(f'<section><h2>{e(label)} <small>({len(by_cat[cat])})</small></h2>{"".join(cards)}</section>')

    body_html = "".join(sections) or '<p class="empty">No findings.</p>'
    errors_html = (
        "".join(f"<li><b>{e(er['plugin'])}</b>: {e(er['error'])}</li>" for er in result.errors)
        or "<li>None</li>"
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>vuln-toolkit — {e(result.target)}</title>
<style>
:root {{ --bg:#0b0f19; --panel:#1e293b; --panel-2:#0f172a; --text:#e2e8f0; --muted:#94a3b8;
        --border:#334155; --crit:#dc2626; --high:#ea580c; --med:#eab308;
        --low:#38bdf8; --info:#64748b; --accent:#38bdf8; }}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text);
        font:14px/1.6 'Segoe UI', system-ui, -apple-system, sans-serif;
        margin:0; padding:32px 40px; }}
header.top {{ background:linear-gradient(135deg,#1e293b,#0f172a);
              border:1px solid var(--border); border-radius:12px;
              padding:24px 28px; margin-bottom:28px; }}
h1 {{ margin:0 0 12px; color:var(--accent); font-size:1.8em; letter-spacing:-0.02em; }}
.meta {{ color:var(--muted); font-size:0.9em; display:flex; gap:20px; flex-wrap:wrap; }}
.meta b {{ color:var(--text); font-weight:600; }}
.summary {{ display:flex; gap:12px; margin-top:16px; flex-wrap:wrap; }}
.summary div {{ padding:8px 14px; border-radius:6px; font-weight:700;
                font-size:0.85em; border:1px solid var(--border); }}
.summary .crit {{ color:var(--crit); border-color:var(--crit); }}
.summary .high {{ color:var(--high); border-color:var(--high); }}
.summary .med  {{ color:var(--med);  border-color:var(--med); }}
.summary .low  {{ color:var(--low);  border-color:var(--low); }}
.summary .info {{ color:var(--info); border-color:var(--info); }}
section {{ margin-bottom:32px; }}
section h2 {{ font-size:1.15em; color:var(--muted); text-transform:uppercase;
              letter-spacing:0.08em; margin:0 0 12px; font-weight:600; }}
section h2 small {{ color:var(--border); font-weight:400; }}
.finding {{ background:var(--panel); border-left:5px solid var(--info);
            border-radius:8px; padding:14px 18px; margin-bottom:10px; }}
.finding.crit {{ border-color:var(--crit); }}
.finding.high {{ border-color:var(--high); }}
.finding.med  {{ border-color:var(--med); }}
.finding.low  {{ border-color:var(--low); }}
.finding header {{ display:flex; align-items:center; gap:10px; margin-bottom:8px; }}
.finding h3 {{ margin:0; font-size:1em; flex:1; font-weight:600; }}
.sev {{ padding:2px 9px; border-radius:4px; font-size:0.7em; font-weight:800;
        color:#000; background:#fff; white-space:nowrap; letter-spacing:0.05em; }}
.finding.crit .sev {{ background:var(--crit); color:#fff; }}
.finding.high .sev {{ background:var(--high); color:#fff; }}
.finding.med  .sev {{ background:var(--med);  color:#000; }}
.finding.low  .sev {{ background:var(--low);  color:#000; }}
.plugin {{ color:var(--muted); font-size:0.78em; font-family:monospace; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ text-align:left; width:110px; color:var(--muted); font-weight:500;
      vertical-align:top; padding:3px 8px 3px 0; font-size:0.85em; }}
td {{ padding:3px 0; font-size:0.9em; word-break:break-word; }}
code {{ background:var(--panel-2); padding:2px 6px; border-radius:4px;
        font-size:0.85em; font-family:monospace; word-break:break-all; }}
a {{ color:var(--accent); }}
.kev {{ background:var(--crit); color:#fff; padding:1px 6px;
        border-radius:3px; font-size:0.75em; margin-left:6px; }}
.errors {{ margin-top:40px; padding-top:20px; border-top:1px solid var(--border); }}
.empty {{ color:var(--muted); font-style:italic; }}
</style></head><body>
<header class="top">
  <h1>vuln-toolkit report</h1>
  <div class="meta">
    <span><b>Target:</b> {e(result.target)}</span>
    <span><b>Mode:</b> {e(result.mode)}</span>
    <span><b>Duration:</b> {result.duration:.2f}s</span>
    <span><b>Plugins:</b> {len(result.plugins_run)}</span>
    <span><b>Suppressed:</b> {result.suppressed}</span>
  </div>
  <div class="summary">
    <div class="crit">CRITICAL {counts['critical']}</div>
    <div class="high">HIGH {counts['high']}</div>
    <div class="med">MEDIUM {counts['medium']}</div>
    <div class="low">LOW {counts['low']}</div>
    <div class="info">INFO {counts['info']}</div>
  </div>
</header>
{body_html}
<div class="errors"><h2>Errors</h2><ul>{errors_html}</ul></div>
</body></html>"""


def emit(result: ScanResult, fmt: str = "console", output: str | None = None) -> None:
    if fmt == "json":
        text = render_json(result)
    elif fmt == "html":
        text = render_html(result)
    else:
        text = render_console(result)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"[+] Report written to {output}", file=sys.stderr)
    else:
        print(text)