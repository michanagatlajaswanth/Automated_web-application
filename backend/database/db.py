
import sqlite3
import json
from pathlib import Path

# Store the database inside backend/database
DB_PATH = Path(__file__).resolve().parent / "scanner.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL,
                findings TEXT NOT NULL DEFAULT '[]',
                total_findings INTEGER NOT NULL DEFAULT 0,
                spider TEXT,
                active_scan TEXT,
                error TEXT,
                scan_mode TEXT NOT NULL DEFAULT 'thorough',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Safely migrate existing databases
        columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        ]

        if "scan_mode" not in columns:
            conn.execute("""
                ALTER TABLE scans
                ADD COLUMN scan_mode TEXT NOT NULL DEFAULT 'thorough'
            """)


def create_scan(scan):
    with get_connection() as conn:
        cursor = conn.execute("""
    INSERT INTO scans (
        target_url, status, findings, total_findings, scan_mode
    )
    VALUES (?, ?, ?, ?, ?)
""", (
    scan["target_url"],
    scan["status"],
    json.dumps(scan.get("findings", [])),
    scan.get("total_findings", 0),
    scan.get("scan_mode", "thorough")
))
        return cursor.lastrowid



def update_scan(scan):
    with get_connection() as conn:
        conn.execute("""
            UPDATE scans
            SET status = ?,
                findings = ?,
                total_findings = ?,
                spider = ?,
                active_scan = ?,
                error = ?,
                scan_mode = ?
            WHERE id = ?
        """, (
            scan["status"],
            json.dumps(scan.get("findings", [])),
            scan.get("total_findings", 0),
            json.dumps(scan["spider"]) if scan.get("spider") is not None else None,
            json.dumps(scan["active_scan"]) if scan.get("active_scan") is not None else None,
            scan.get("error"),
            scan.get("scan_mode", "thorough"),
            scan["id"]
        ))



def get_all_scans():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()

    return [row_to_dict(row) for row in rows]


def get_scan_by_id(scan_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

    return row_to_dict(row) if row else None


def row_to_dict(row):
    if row is None:
        return None

    return {
        "id": row["id"],
        "target_url": row["target_url"],
        "status": row["status"],
        "findings": json.loads(row["findings"]),
        "total_findings": row["total_findings"],
        "spider": json.loads(row["spider"]) if row["spider"] else None,
        "active_scan": json.loads(row["active_scan"]) if row["active_scan"] else None,
        "error": row["error"],
        "scan_mode": row["scan_mode"],
        "created_at": row["created_at"]
    }
