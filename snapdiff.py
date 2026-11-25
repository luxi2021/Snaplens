"""
snapshots.py — read config files, hash them, compare two captures.

Three things this module does:

1. capture_file_snapshot(path)  → read a file, normalize it, return {sha256, lines, ...}
2. compute_line_drift(old, new) → tell you what changed line-by-line
3. detect_snapshot_drift(a, b)  → run the comparison and log an audit row

Nothing here talks to Flask. It's pure logic + DB auditing via `testdb`.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import testdb


# Files we allow by default. This list is *roots* — /etc/sudoers.d is a
# directory, so callers should pass files inside it, e.g.
# "/etc/sudoers.d/90-cloud-init-users".
DEFAULT_ALLOWED_TARGETS: tuple[str, ...] = (
    "/etc/ssh/sshd_config",
    "/etc/sysctl.conf",
    "/etc/hosts",
    "/etc/sudoers.d",
)

# Don't try to read anything bigger than this into memory. 1 MiB is plenty
# for a config file; anything larger is probably a mistake (or a target).
MAX_SNAPSHOT_BYTES = 1_048_576


def _normalize_lines(raw_text: str) -> list[str]:
    """
    Convert CRLF/CR to LF and strip trailing spaces on each line.

    We do this so that purely cosmetic differences (Windows vs Unix line
    endings, a stray space after "PermitRootLogin yes") don't show up as
    drift. The tradeoff: a whitespace-significant change in some configs
    (sudoers has a few) would be invisible. Acceptable for our purposes.
    """
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    return [line.rstrip() for line in normalized.splitlines()]


def compute_sha256(content: str) -> str:
    """SHA-256 of a string, as lowercase hex. Deterministic."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def resolve_allowed_path(
    target_path: str,
    allowed_roots: list[Path] | None = None,
) -> Path:
    """
    Turn `target_path` into a resolved Path and make sure it's safe to read.

    'Safe' means: it's absolute, it exists, it's a regular file (not a
    directory or a device), and — if `allowed_roots` was given — it lives
    inside one of those roots after following symlinks.
    """
    candidate = Path(target_path)
    if not candidate.is_absolute():
        raise ValueError("Snapshot target path must be an absolute path.")

    resolved = candidate.resolve(strict=False)
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"Target configuration file does not exist: {resolved}")

    if allowed_roots:
        resolved_roots = [root.resolve(strict=False) for root in allowed_roots]
        # Two cases we care about: the file *is* one of the roots, or it's
        # nested under one. `root in resolved.parents` handles nesting;
        # `resolved == root` handles the identity case.
        if not any(resolved == root or root in resolved.parents for root in resolved_roots):
            raise PermissionError(f"Target path is outside permitted roots: {resolved}")

    return resolved


def _audit_snapshot_event(
    actor: dict[str, Any] | None,
    action: str,
    target_id: str,
    details: dict[str, Any],
) -> None:
    """
    Write an audit row, but only if we actually have an actor.

    Most calls come from request handlers where the actor is `g.user`, but
    some come from tests or CLIs with no session — those pass actor=None
    and skip the audit entirely.
    """
    if not actor:
        return
    testdb.log_audit_event(
        actor_id=actor.get("id"),
        actor_username=actor.get("username", "unknown"),
        actor_role=actor.get("role", "unknown"),
        action=action,
        target_type="config_file",
        target_id=target_id,
        details=json.dumps(details),
    )


def capture_file_snapshot(
    target_path: str,
    actor: dict[str, Any] | None = None,
    allowed_roots: list[Path] | None = None,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """
    Read one config file and return a snapshot dict:

        {target_path, sha256, line_count, lines, captured_at}

    Raises FileNotFoundError / PermissionError / ValueError for the obvious
    reasons (missing file, outside roots, too big). The audit row is written
    *after* the snapshot is built, so a failed capture never leaves an
    "SNAPSHOT_CAPTURED" entry in the log.
    """
    resolved = resolve_allowed_path(target_path, allowed_roots=allowed_roots)

    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds maximum allowed size ({max_bytes} bytes): {resolved}")

    raw_text = resolved.read_text(encoding="utf-8", errors="replace")
    lines = _normalize_lines(raw_text)
    digest = compute_sha256("\n".join(lines))

    snapshot = {
        "target_path": str(resolved),
        "sha256": digest,
        "line_count": len(lines),
        "lines": lines,
        "captured_at": testdb.utc_now_iso(),
    }

    _audit_snapshot_event(
        actor,
        action="SNAPSHOT_CAPTURED",
        target_id=str(resolved),
        details={"sha256": digest, "line_count": len(lines)},
    )
    return snapshot


def compute_line_drift(
    baseline_lines: list[str],
    current_lines: list[str],
) -> dict[str, Any]:
    """
    Tell you what changed between two versions of a config file.

    Three buckets:

      added    — a line in `current` that wasn't anywhere in `baseline`
      removed  — a line in `baseline` that's nowhere in `current`
      modified — same position, different content (we pair line-by-line)

    A line that just moved (say, line 5 → line 12) will show up as *both*
    an add and a remove, not as "modified". That's intentional: we can't
    tell a move from a delete+insert without more context, and being
    conservative is safer.
    """
    baseline_set = set(baseline_lines)
    current_set = set(current_lines)

    removed = [line for line in baseline_lines if line not in current_set]
    added = [line for line in current_lines if line not in baseline_set]

    # Positional comparison for "modified". The loop walks up to whichever
    # side is longer so we don't miss a change at the tail.
    modified: list[dict[str, Any]] = []
    for idx in range(max(len(baseline_lines), len(current_lines))):
        old_line = baseline_lines[idx] if idx < len(baseline_lines) else None
        new_line = current_lines[idx] if idx < len(current_lines) else None
        if old_line is not None and new_line is not None and old_line != new_line:
            modified.append({
                "line_number": idx + 1,
                "before": old_line,
                "after": new_line,
            })

    return {
        "has_drift": bool(added or removed or modified),
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
        },
        "added": added,
        "removed": removed,
        "modified": modified,
    }


def _empty_drift(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """The 'nothing changed' result, shaped exactly like a real drift result."""
    return {
        "target_path": current.get("target_path", ""),
        "baseline_sha256": baseline.get("sha256"),
        "current_sha256": current.get("sha256"),
        "has_drift": False,
        "summary": {"added_count": 0, "removed_count": 0, "modified_count": 0},
        "added": [],
        "removed": [],
        "modified": [],
    }
# An additional functionality for comparing snapshots of a linux host
def capture_and_diff_snapshot(
    host_label,
    snapshot_tag,
    target_path,
    actor,
    allowed_roots=None,
    review_status="pending_review",
    max_bytes=1_048_576,
):
    resolved = resolve_allowed_path(target_path, allowed_roots=allowed_roots)
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"Target file exceeds {max_bytes} bytes: {resolved}")

    current_lines = _normalize_lines(
        resolved.read_text(encoding="utf-8", errors="replace")
    )
    current_digest = compute_sha256("\n".join(current_lines))

    parent_snap = testdb.latest_snap_for_host(host_label)
    parent_id = int(parent_snap["id"]) if parent_snap else None

    if parent_snap is None:
        # first snapshot for this host — nothing to diff against
        diff = {
            "has_drift": False,
            "added_count": 0,
            "modified_count": 0,
            "removed_count": 0,
            "added": [],
            "modified": [],
            "removed": [],
        }
    else:
        baseline_lines = testdb.extract_snap_lines(parent_snap)
        raw_diff = compute_line_drift(baseline_lines, current_lines)
        # compute_line_drift nests counts under "summary" — flatten so the
        # rest of this function doesn't have to care
        diff = {
            "has_drift": raw_diff["has_drift"],
            **raw_diff["summary"],
            "added": raw_diff["added"],
            "modified": raw_diff["modified"],
            "removed": raw_diff["removed"],
        }

    diff_payload = {
        "target_path": str(resolved),
        "sha256": current_digest,
        "lines": current_lines,
        "added": diff["added"],
        "modified": diff["modified"],
        "removed": diff["removed"],
    }

    actor_id = actor.get("id")
    actor_username = actor.get("username", "unknown")
    actor_role = actor.get("role", "unknown")

    snapshot_id = testdb.create_snap(
        host_label,
        snapshot_tag,
        actor_id,
        parent_snapshot_id=parent_id,
        added_count=diff["added_count"],
        modified_count=diff["modified_count"],
        removed_count=diff["removed_count"],
        diff_json=json.dumps(diff_payload),
        review_status=review_status,
    )

    testdb.log_audit_event(
        actor_id=actor_id,
        actor_username=actor_username,
        actor_role=actor_role,
        action="SNAPSHOT_CAPTURED",
        target_type="snapshot",
        target_id=str(snapshot_id),
        details=json.dumps({
            "host_label": host_label,
            "snapshot_tag": snapshot_tag,
            "target_path": str(resolved),
            "parent_snapshot_id": parent_id,
            "added_count": diff["added_count"],
            "modified_count": diff["modified_count"],
            "removed_count": diff["removed_count"],
        }),
    )

    return {
        "id": snapshot_id,
        "host_label": host_label,
        "snapshot_tag": snapshot_tag,
        "parent_snapshot_id": parent_id,
        "sha256": current_digest,
        **diff,
    }
#
#
def detect_snapshot_drift(
    baseline_snapshot: dict[str, Any],
    current_snapshot: dict[str, Any],
    actor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Compare two snapshots. If the hashes match, short-circuit to the empty
    result — no point diffing thousands of identical lines. Otherwise run
    `compute_line_drift` on the stored line lists.

    Always writes a DRIFT_CHECKED audit row if an actor is supplied, so
    reviewers can trace who ran a comparison and when.
    """
    if baseline_snapshot.get("sha256") == current_snapshot.get("sha256"):
        drift = _empty_drift(baseline_snapshot, current_snapshot)
    else:
        line_diff = compute_line_drift(
            baseline_snapshot.get("lines", []),
            current_snapshot.get("lines", []),
        )
        drift = {
            "target_path": current_snapshot.get("target_path", ""),
            "baseline_sha256": baseline_snapshot.get("sha256"),
            "current_sha256": current_snapshot.get("sha256"),
            **line_diff,
        }

    _audit_snapshot_event(
        actor,
        action="DRIFT_CHECKED",
        target_id=drift["target_path"],
        details={
            "has_drift": drift["has_drift"],
            "summary": drift["summary"],
        },
    )
    return drift