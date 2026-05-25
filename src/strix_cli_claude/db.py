"""SQLite-backed persistent store for bounty programs, targets, and findings.

Database lives at ~/.strix/strix.db (mode 0700 on parent dir).
Single writer pattern is enough for this workload; concurrent claims are
serialized with BEGIN IMMEDIATE in claim_next_target().

Schema versions:
  1 — h1-only. programs PK = handle. targets UNIQUE (program_handle, asset_type, identifier).
  2 — multi-platform. programs PK = (source, handle). targets UNIQUE
      (source, program_handle, asset_type, identifier). source ∈ {'h1', 'intigriti'}.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_DIR = Path.home() / ".strix"
DB_PATH = DB_DIR / "strix.db"

# How long a row may stay 'in_progress' before another claimer can steal it.
STALE_CLAIM_SECONDS = 4 * 3600

SCHEMA_VERSION = 2

VALID_SOURCES = ("h1", "intigriti")


def _ensure_dir() -> None:
    DB_DIR.mkdir(mode=0o700, exist_ok=True)
    # If it pre-existed with looser perms, tighten it.
    try:
        os.chmod(DB_DIR, 0o700)
    except PermissionError:
        pass


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    _ensure_dir()
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create tables and run migrations if needed."""
    with get_conn() as conn:
        current = conn.execute("PRAGMA user_version").fetchone()[0]

        if current < 1:
            # Fresh install — create v2 schema directly.
            _create_v2_schema(conn)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            return

        if current < 2:
            _migrate_v1_to_v2(conn)
            conn.execute("PRAGMA user_version=2")


def _create_v2_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        BEGIN;

        CREATE TABLE IF NOT EXISTS programs (
            source           TEXT NOT NULL DEFAULT 'h1',
            handle           TEXT NOT NULL,
            name             TEXT,
            policy_url       TEXT,
            offers_bounty    INTEGER NOT NULL DEFAULT 0,
            submission_state TEXT,
            last_synced_at   INTEGER,
            archived         INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (source, handle)
        );

        CREATE TABLE IF NOT EXISTS targets (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            source              TEXT NOT NULL DEFAULT 'h1',
            program_handle      TEXT NOT NULL,
            asset_type          TEXT NOT NULL,
            identifier          TEXT NOT NULL,
            eligible_for_bounty INTEGER NOT NULL DEFAULT 1,
            max_severity        TEXT,
            instruction         TEXT,
            scan_status         TEXT NOT NULL DEFAULT 'pending',
                                  -- pending|in_progress|done|skipped|error
            scan_started_at     INTEGER,
            scan_finished_at    INTEGER,
            summary             TEXT,
            UNIQUE(source, program_handle, asset_type, identifier),
            FOREIGN KEY (source, program_handle)
                REFERENCES programs(source, handle) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_targets_status   ON targets(scan_status);
        CREATE INDEX IF NOT EXISTS idx_targets_program  ON targets(source, program_handle);
        CREATE INDEX IF NOT EXISTS idx_targets_asset    ON targets(asset_type);
        CREATE INDEX IF NOT EXISTS idx_targets_source   ON targets(source);

        CREATE TABLE IF NOT EXISTS findings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER NOT NULL
                            REFERENCES targets(id) ON DELETE CASCADE,
            title         TEXT NOT NULL,
            severity      TEXT,
            vuln_type     TEXT,
            asset         TEXT,
            poc_path      TEXT,
            notes         TEXT,
            status        TEXT NOT NULL DEFAULT 'candidate',
                            -- candidate|confirmed|rejected|submitted|duplicate
            h1_report_id  TEXT,
            created_at    INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);

        COMMIT;
        """
    )


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """Add `source` column and composite keys. v1 rows default to source='h1'."""
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(
        """
        BEGIN;

        ALTER TABLE programs RENAME TO programs_v1;
        ALTER TABLE targets  RENAME TO targets_v1;

        CREATE TABLE programs (
            source           TEXT NOT NULL DEFAULT 'h1',
            handle           TEXT NOT NULL,
            name             TEXT,
            policy_url       TEXT,
            offers_bounty    INTEGER NOT NULL DEFAULT 0,
            submission_state TEXT,
            last_synced_at   INTEGER,
            archived         INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (source, handle)
        );

        CREATE TABLE targets (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            source              TEXT NOT NULL DEFAULT 'h1',
            program_handle      TEXT NOT NULL,
            asset_type          TEXT NOT NULL,
            identifier          TEXT NOT NULL,
            eligible_for_bounty INTEGER NOT NULL DEFAULT 1,
            max_severity        TEXT,
            instruction         TEXT,
            scan_status         TEXT NOT NULL DEFAULT 'pending',
            scan_started_at     INTEGER,
            scan_finished_at    INTEGER,
            summary             TEXT,
            UNIQUE(source, program_handle, asset_type, identifier),
            FOREIGN KEY (source, program_handle)
                REFERENCES programs(source, handle) ON DELETE CASCADE
        );

        INSERT INTO programs
            (source, handle, name, policy_url, offers_bounty, submission_state, last_synced_at, archived)
        SELECT 'h1', handle, name, policy_url, offers_bounty, submission_state, last_synced_at, archived
        FROM programs_v1;

        INSERT INTO targets
            (id, source, program_handle, asset_type, identifier, eligible_for_bounty,
             max_severity, instruction, scan_status, scan_started_at, scan_finished_at, summary)
        SELECT id, 'h1', program_handle, asset_type, identifier, eligible_for_bounty,
               max_severity, instruction, scan_status, scan_started_at, scan_finished_at, summary
        FROM targets_v1;

        DROP TABLE targets_v1;
        DROP TABLE programs_v1;

        CREATE INDEX IF NOT EXISTS idx_targets_status   ON targets(scan_status);
        CREATE INDEX IF NOT EXISTS idx_targets_program  ON targets(source, program_handle);
        CREATE INDEX IF NOT EXISTS idx_targets_asset    ON targets(asset_type);
        CREATE INDEX IF NOT EXISTS idx_targets_source   ON targets(source);

        COMMIT;
        """
    )
    conn.execute("PRAGMA foreign_keys=ON")


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

def upsert_program(
    conn: sqlite3.Connection,
    handle: str,
    name: str | None,
    policy_url: str | None,
    offers_bounty: bool,
    submission_state: str | None = None,
    source: str = "h1",
) -> None:
    if source not in VALID_SOURCES:
        raise ValueError(f"invalid source: {source}")
    conn.execute(
        """
        INSERT INTO programs
            (source, handle, name, policy_url, offers_bounty, submission_state, last_synced_at, archived)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        ON CONFLICT(source, handle) DO UPDATE SET
            name             = excluded.name,
            policy_url       = excluded.policy_url,
            offers_bounty    = excluded.offers_bounty,
            submission_state = excluded.submission_state,
            last_synced_at   = excluded.last_synced_at,
            archived         = 0
        """,
        (
            source,
            handle,
            name,
            policy_url,
            1 if offers_bounty else 0,
            submission_state,
            int(time.time()),
        ),
    )


def list_programs(
    handle_filter: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    where: list[str] = ["archived=0"]
    params: list[Any] = []
    if handle_filter:
        where.append("handle LIKE ?")
        params.append(f"%{handle_filter}%")
    if source:
        where.append("source = ?")
        params.append(source)
    sql = f"SELECT * FROM programs WHERE {' AND '.join(where)} ORDER BY source, handle"
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def mark_programs_archived_except(
    handles: list[str],
    source: str = "h1",
) -> None:
    """Mark programs of this source NOT in `handles` as archived. Call after a full sync."""
    if not handles:
        return
    placeholders = ",".join("?" * len(handles))
    with get_conn() as conn:
        conn.execute(
            f"UPDATE programs SET archived=1"
            f" WHERE source=? AND handle NOT IN ({placeholders})",
            [source, *handles],
        )


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def upsert_target(
    conn: sqlite3.Connection,
    program_handle: str,
    asset_type: str,
    identifier: str,
    eligible_for_bounty: bool,
    max_severity: str | None,
    instruction: str | None,
    source: str = "h1",
) -> None:
    if source not in VALID_SOURCES:
        raise ValueError(f"invalid source: {source}")
    conn.execute(
        """
        INSERT INTO targets
            (source, program_handle, asset_type, identifier, eligible_for_bounty,
             max_severity, instruction, scan_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        ON CONFLICT(source, program_handle, asset_type, identifier) DO UPDATE SET
            eligible_for_bounty = excluded.eligible_for_bounty,
            max_severity        = excluded.max_severity,
            instruction         = excluded.instruction
        """,
        (
            source,
            program_handle,
            asset_type,
            identifier,
            1 if eligible_for_bounty else 0,
            max_severity,
            instruction,
        ),
    )


def claim_next_target(
    program_handles: list[str] | None = None,
    asset_types: list[str] | None = None,
    source: str | None = None,
) -> dict[str, Any] | None:
    """Atomically claim the next pending (or stale in-progress) target.

    Returns the target row as a dict, or None if nothing eligible.
    Caller becomes responsible for calling mark_target() to settle the row.
    """
    stale_cutoff = int(time.time()) - STALE_CLAIM_SECONDS
    where_parts = [
        "(scan_status = 'pending'"
        " OR (scan_status = 'in_progress' AND COALESCE(scan_started_at, 0) < ?))"
    ]
    params: list[Any] = [stale_cutoff]

    if source:
        where_parts.append("source = ?")
        params.append(source)

    if program_handles:
        ph = ",".join("?" * len(program_handles))
        where_parts.append(f"program_handle IN ({ph})")
        params.extend(program_handles)

    if asset_types:
        ph = ",".join("?" * len(asset_types))
        where_parts.append(f"asset_type IN ({ph})")
        params.extend(asset_types)

    where_sql = " AND ".join(where_parts)

    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"SELECT * FROM targets WHERE {where_sql} ORDER BY id LIMIT 1",
            params,
        ).fetchone()

        if row is None:
            conn.execute("COMMIT")
            return None

        conn.execute(
            "UPDATE targets SET scan_status='in_progress', scan_started_at=?"
            " WHERE id=?",
            (int(time.time()), row["id"]),
        )
        conn.execute("COMMIT")
        return dict(row)


def mark_target(
    target_id: int,
    status: str,
    summary: str | None = None,
) -> None:
    if status not in ("pending", "in_progress", "done", "skipped", "error"):
        raise ValueError(f"invalid scan_status: {status}")
    with get_conn() as conn:
        conn.execute(
            "UPDATE targets"
            " SET scan_status=?, scan_finished_at=?, summary=COALESCE(?, summary)"
            " WHERE id=?",
            (status, int(time.time()), summary, target_id),
        )


def scan_status_counts(
    program_handle: str | None = None,
    source: str | None = None,
) -> dict[str, int]:
    where: list[str] = []
    params: list[Any] = []
    if program_handle:
        where.append("program_handle=?")
        params.append(program_handle)
    if source:
        where.append("source=?")
        params.append(source)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT scan_status, COUNT(*) n FROM targets{where_sql} GROUP BY scan_status",
            params,
        ).fetchall()
    return {r["scan_status"]: r["n"] for r in rows}


def scope_summary(
    program_handle: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    """Return per-(program × asset_type) counts.

    If program_handle is given, return rows for that program only with status breakdown.
    Otherwise return one row per (source, program, asset_type) with total + pending counts.
    """
    with get_conn() as conn:
        if program_handle:
            params: list[Any] = [program_handle]
            extra = ""
            if source:
                extra = " AND source=?"
                params.append(source)
            rows = conn.execute(
                f"""
                SELECT source,
                       asset_type,
                       COUNT(*) AS total,
                       SUM(scan_status='pending')      AS pending,
                       SUM(scan_status='in_progress')  AS in_progress,
                       SUM(scan_status='done')         AS done,
                       SUM(scan_status='skipped')      AS skipped,
                       SUM(scan_status='error')        AS errored
                FROM targets
                WHERE program_handle=?{extra}
                GROUP BY source, asset_type
                ORDER BY total DESC
                """,
                params,
            ).fetchall()
        else:
            params2: list[Any] = []
            extra2 = ""
            if source:
                extra2 = " AND t.source=?"
                params2.append(source)
            rows = conn.execute(
                f"""
                SELECT t.source,
                       t.program_handle,
                       p.offers_bounty,
                       t.asset_type,
                       COUNT(*) AS total,
                       SUM(t.scan_status='pending') AS pending,
                       SUM(t.scan_status='done')    AS done
                FROM targets t
                JOIN programs p
                  ON p.source = t.source AND p.handle = t.program_handle
                WHERE p.archived = 0{extra2}
                GROUP BY t.source, t.program_handle, t.asset_type
                ORDER BY total DESC
                """,
                params2,
            ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def create_finding(
    target_id: int,
    title: str,
    severity: str | None,
    vuln_type: str | None,
    asset: str | None,
    poc_path: str | None,
    notes: str | None,
) -> int:
    now = int(time.time())
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO findings
                (target_id, title, severity, vuln_type, asset, poc_path, notes,
                 status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'candidate', ?, ?)
            """,
            (target_id, title, severity, vuln_type, asset, poc_path, notes, now, now),
        )
        return int(cur.lastrowid)


def update_finding_status(
    finding_id: int,
    status: str,
    extra_note: str | None = None,
) -> None:
    if status not in ("candidate", "confirmed", "rejected", "submitted", "duplicate"):
        raise ValueError(f"invalid finding status: {status}")
    now = int(time.time())
    with get_conn() as conn:
        if extra_note:
            conn.execute(
                "UPDATE findings"
                " SET status=?, notes=COALESCE(notes,'') || ?, updated_at=?"
                " WHERE id=?",
                (status, f"\n[{status}] {extra_note}", now, finding_id),
            )
        else:
            conn.execute(
                "UPDATE findings SET status=?, updated_at=? WHERE id=?",
                (status, now, finding_id),
            )


def list_findings(
    status: str | None = None,
    program_handle: str | None = None,
    source: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    where: list[str] = []
    params: list[Any] = []
    if status:
        where.append("f.status = ?")
        params.append(status)
    if program_handle:
        where.append("t.program_handle = ?")
        params.append(program_handle)
    if source:
        where.append("t.source = ?")
        params.append(source)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT f.*,
                   t.source,
                   t.program_handle,
                   t.asset_type,
                   t.identifier AS target_identifier
            FROM findings f
            JOIN targets  t ON t.id = f.target_id
            {where_sql}
            ORDER BY f.created_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [dict(r) for r in rows]
