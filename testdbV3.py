"""
Test-db.py — SQLite persistence layer for Snaplens.

Tables
------
users       : authenticated accounts (engineer / reviewer / admin)
snapshots   : filesystem diffs captured from hosts, with review state
audit_logs  : append-only record of security-relevant events

Conventions
-----------
* All timestamps are stored as UTC ISO-8601 strings (see `utc_now_iso`).
* Foreign keys are enforced on every connection.
* "Credentials check" helpers intentionally return None for both
  unknown-user and bad-password so callers cannot enumerate usernames.
"""
from __future__ import annotations

import os
import sqlite3
import json
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

DEFAULT_DB_PATH = os.environ.get("SNAPLENS_DB_PATH", "snaplens.db")
VALID_ROLES = ("engineer", "reviewer", "admin")

# Selected whenever we load a user. Kept in one place so the two
# get_user_* functions can never drift apart.
_USER_COLUMNS = "id, username, password_hash, role, is_active, created_at"


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #

def utc_now_iso() -> str:
    """Return the current UTC time as a timezone-aware ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a connection with row access by name and foreign keys enforced."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

# This part of code helps to save snapshots using parameterized queries in a reliable and safe fashion
# These are termed as SQLite helpers used for retrieving particular snapshots using id / target path. -- Version 2
def create_snap(
    host_label,
    snapshot_tag,
    captured_by,
    parent_snapshot_id=None,
    added_count=0,
    modified_count=0,
    removed_count=0,
    diff_json="{}",
    review_status: str = "pending_review",
    reviewed_by=None,
    review_notes="",
):
    now = utc_now_iso()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO snapshots (
                host_label, snapshot_tag, captured_by, parent_snapshot_id,
                added_count, modified_count, removed_count, diff_json,
                review_status, reviewed_by, review_notes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host_label, snapshot_tag, captured_by, parent_snapshot_id,
                int(added_count), int(modified_count), int(removed_count),
                diff_json, review_status, reviewed_by, review_notes,
                now, now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_snapshot_by_id(snapshot_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots WHERE id = ?", (int(snapshot_id),)
        ).fetchone()
        return dict(row) if row else None


def latest_snap_for_host(host_label):
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM snapshots
            WHERE host_label = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (host_label,),
        ).fetchone()
        return dict(row) if row else None


def list_snapshot(host_label=None, limit=50):
    # clamp — a caller asking for 10000 rows would be rude
    limit = max(1, min(int(limit), 500))
    with get_connection() as conn:
        if host_label:
            rows = conn.execute(
                "SELECT * FROM snapshots WHERE host_label = ? "
                "ORDER BY id DESC LIMIT ?",
                (host_label, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM snapshots ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def update_snapshot_reviews(snapshot_id, review_status, reviewed_by, review_notes=""):
    now = utc_now_iso()
    with get_connection() as conn:
        cur = conn.execute(
            """
            UPDATE snapshots
            SET review_status = ?,
                reviewed_by = ?,
                review_notes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (review_status, reviewed_by, review_notes, now, int(snapshot_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    
# This part of code helps to reconstruct lines safely while the app compares a newly taken snapshot with an earlier snapshot.
# *Version 3*
def extract_snap_lines(snapshot_row: dict | None) -> list[str]:
    """Extract stored normalized config lines from a snapshot row's diff_json."""
    if not snapshot_row:
        return []
    raw_diff = snapshot_row.get("diff_json") or "{}"
    try:
        parsed = json.loads(raw_diff)
    except (TypeError, ValueError):
        return []
    if isinstance(parsed, dict) and isinstance(parsed.get("lines"), list): # if previous snapshot exists
        return [str(line) for line in parsed["lines"]]
    return []


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create all tables and indexes if they do not already exist."""
    schema_sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('engineer', 'reviewer', 'admin')),
        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_label TEXT NOT NULL,
        snapshot_tag TEXT NOT NULL,
        captured_by INTEGER NOT NULL,
        parent_snapshot_id INTEGER,
        added_count INTEGER NOT NULL DEFAULT 0,
        modified_count INTEGER NOT NULL DEFAULT 0,
        removed_count INTEGER NOT NULL DEFAULT 0,
        diff_json TEXT NOT NULL DEFAULT '{}',
        review_status TEXT NOT NULL DEFAULT 'pending_review'
            CHECK (review_status IN ('pending_review', 'approved', 'flagged', 'remediated')),
        reviewed_by INTEGER,
        review_notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (captured_by) REFERENCES users (id),
        FOREIGN KEY (parent_snapshot_id) REFERENCES snapshots (id),
        FOREIGN KEY (reviewed_by) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER,
        actor_username TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT,
        details TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (actor_id) REFERENCES users (id)
    );

    -- Supports "list recent snapshots for a host" queries.
    CREATE INDEX IF NOT EXISTS idx_snapshots_host_created
        ON snapshots (host_label, created_at);

    -- Supports time-ordered audit-log browsing.
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created
        ON audit_logs (created_at);
    """
    with get_connection(db_path) as conn:
        conn.executescript(schema_sql)


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

def create_user(
    username: str,
    password: str,
    role: str,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Create a user and return the new row id. Raises ValueError on bad input."""
    clean_username = username.strip()
    if not clean_username or len(password) < 8:
        raise ValueError("Username is required and password must be at least 8 characters.")
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Expected one of {VALID_ROLES}.")

    password_hash = generate_password_hash(password)
    now = utc_now_iso()

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (clean_username, password_hash, role, now),
        )
        return int(cursor.lastrowid)


def get_user_by_username(username: str, db_path: str = DEFAULT_DB_PATH) -> sqlite3.Row | None:
    """Fetch a user by username (case-sensitive, whitespace trimmed)."""
    with get_connection(db_path) as conn:
        return conn.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()


def get_user_by_id(user_id: int, db_path: str = DEFAULT_DB_PATH) -> sqlite3.Row | None:
    """Fetch a user by primary key."""
    with get_connection(db_path) as conn:
        return conn.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def set_user_password(
    username: str,
    new_password: str,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    """
    Replace a user's password hash. Returns True if a row was updated.

    Useful for rotating demo credentials without deleting the database.
    """
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (generate_password_hash(new_password), username.strip()),
        )
        return cursor.rowcount > 0


def verify_user_credentials(
    username: str,
    password: str,
    db_path: str = DEFAULT_DB_PATH,
) -> sqlite3.Row | None:
    """
    Return the user row if the password matches AND the account is active.

    Returning None for both "no such user" and "wrong password" prevents
    callers (and attackers) from distinguishing the two cases.
    """
    user = get_user_by_username(username, db_path=db_path)
    if user is None or user["is_active"] != 1:
        return None
    return user if check_password_hash(user["password_hash"], password) else None


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #

def log_audit_event(
    actor_id: int | None,
    actor_username: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: str | None = None,
    details: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Append one audit-log row. Never raises on missing optional fields."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                actor_id, actor_username, actor_role, action,
                target_type, target_id, details, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (actor_id, actor_username, actor_role, action,
             target_type, target_id, details, utc_now_iso()),
        )


# --------------------------------------------------------------------------- #
# Demo seeding
# --------------------------------------------------------------------------- #

def seed_default_users(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Create the three demo accounts if they don't exist yet.

    Passwords are read from environment variables. The hardcoded fallbacks
    exist only for local development — replace them (or delete this function)
    before any shared deployment.
    """
    seed_accounts = [
        ("eng_demo",   "SNAPLENS_ENG_PASS",   "E#g|N@*r0!", "engineer"),
        ("rev_demo",   "SNAPLENS_REV_PASS",   "R@vI#w$1%",  "reviewer"),
        ("admin_demo", "SNAPLENS_ADMIN_PASS", "@D!%$n2*",   "admin"),
    ]
    for username, env_var, fallback, role in seed_accounts:
        if get_user_by_username(username, db_path=db_path) is None:
            password = os.environ.get(env_var, fallback)
            create_user(username, password, role, db_path=db_path)
