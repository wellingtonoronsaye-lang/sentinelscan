"""Small SQLite persistence layer for CTI scan results."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    overall_verdict TEXT NOT NULL,
    sources_scanned INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS provider_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.0,
    details_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES ioc_scans(id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_scans_ioc ON ioc_scans(ioc);
CREATE INDEX IF NOT EXISTS idx_ioc_scans_verdict ON ioc_scans(overall_verdict);
CREATE INDEX IF NOT EXISTS idx_provider_results_scan_id ON provider_results(scan_id);
"""


def init_db(db_path: str) -> None:
    """Create the SQLite database and required tables if they do not exist."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)


def save_scan(
    db_path: str,
    *,
    ioc: str,
    ioc_type: str,
    overall_verdict: str,
    results: list[dict[str, Any]],
) -> int:
    """Persist one scan and its provider results, returning the scan id."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO ioc_scans (ioc, ioc_type, overall_verdict, sources_scanned)
            VALUES (?, ?, ?, ?)
            """,
            (ioc, ioc_type, overall_verdict, len(results)),
        )
        scan_id = int(cursor.lastrowid)

        conn.executemany(
            """
            INSERT INTO provider_results
                (scan_id, provider, verdict, confidence, details_json, error)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    result.get("source", "unknown"),
                    result.get("verdict", "unknown"),
                    float(result.get("confidence", 0.0) or 0.0),
                    json.dumps(result.get("details", {})),
                    result.get("error"),
                )
                for result in results
            ],
        )
        return scan_id
