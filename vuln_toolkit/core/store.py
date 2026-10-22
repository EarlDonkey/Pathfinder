from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from vuln_toolkit.core.engine import ScanResult


def _get_db_path() -> Path:
    # Store in user's home directory to persist across project folders
    db_dir = Path.home() / ".vuln-toolkit"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "scans.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                timestamp REAL NOT NULL,
                duration REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT NOT NULL,
                scan_id INTEGER NOT NULL,
                plugin TEXT,
                title TEXT,
                severity TEXT,
                cve TEXT,
                kev INTEGER,
                description TEXT,
                remediation TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)


def save_scan(result: ScanResult) -> int:
    """Saves a scan result to the database. Returns the scan_id."""
    init_db()
    with _get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, mode, timestamp, duration) VALUES (?, ?, ?, ?)",
            (result.target, result.mode, time.time(), result.duration)
        )
        scan_id = cursor.lastrowid

        for f in result.findings:
            cursor.execute(
                """INSERT INTO findings 
                   (finding_id, scan_id, plugin, title, severity, cve, kev, description, remediation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (f.id, scan_id, f.plugin, f.title, f.severity.value,
                 f.cve, int(f.kev) if f.kev else 0, f.description, f.remediation)
            )
        conn.commit()
    return scan_id


def get_previous_scan(target: str) -> tuple[int, list[dict]] | None:
    """Returns (scan_id, findings) for the 2nd most recent scan of this target."""
    init_db()
    with _get_conn() as conn:
        cursor = conn.cursor()
        # Get all scans for target, descending
        cursor.execute(
            "SELECT id, timestamp FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT 2",
            (target,)
        )
        rows = cursor.fetchall()
        if len(rows) < 2:
            return None  # Need at least 2 scans to diff

        previous_scan_id = rows[1]["id"]
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (previous_scan_id,))
        findings = [dict(r) for r in cursor.fetchall()]
        return previous_scan_id, findings


def get_latest_scan(target: str) -> tuple[int, list[dict]] | None:
    """Returns (scan_id, findings) for the most recent scan of this target."""
    init_db()
    with _get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
            (target,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        scan_id = row["id"]
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        findings = [dict(r) for r in cursor.fetchall()]
        return scan_id, findings