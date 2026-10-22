from __future__ import annotations

from dataclasses import dataclass

from vuln_toolkit.core.plugin_base import SEVERITY_ORDER, Severity


@dataclass
class DiffResult:
    target: str
    new: list[dict]
    resolved: list[dict]
    unchanged: list[dict]

    def print_summary(self):
        print("=" * 60)
        print(f"Diff Report: {self.target}")
        print("=" * 60)
        
        print(f"\n[+] NEW FINDINGS: {len(self.new)}")
        for f in self.new:
            print(f"  [{f['severity'].upper()}] {f['title']}")

        print(f"\n[-] RESOLVED (Fixed): {len(self.resolved)}")
        for f in self.resolved:
            print(f"  [{f['severity'].upper()}] {f['title']}")

        print(f"\n[=] UNCHANGED: {len(self.unchanged)}")
        print()


def diff_scans(target: str, old_findings: list[dict], new_findings: list[dict]) -> DiffResult:
    # Map by finding_id for O(1) lookup
    old_map = {f["finding_id"]: f for f in old_findings}
    new_map = {f["finding_id"]: f for f in new_findings}

    new_items = []
    unchanged = []
    
    # Find new and unchanged
    for fid, f in new_map.items():
        if fid not in old_map:
            new_items.append(f)
        else:
            unchanged.append(f)

    # Find resolved (were in old, not in new)
    resolved = [f for fid, f in old_map.items() if fid not in new_map]

    # Sort by severity
    def sort_key(f):
        try:
            return -SEVERITY_ORDER[Severity(f["severity"])]
        except ValueError:
            return 0

    new_items.sort(key=sort_key)
    resolved.sort(key=sort_key)

    return DiffResult(target=target, new=new_items, resolved=resolved, unchanged=unchanged)