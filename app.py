"""
app.py — application factory and route table for Snaplens.

Boot order matters
------------------
1. Configure Flask (secret key + cookie flags).
2. Attach CSRF protection to the app BEFORE any form renders.
3. Initialise the DB and seed demo users (both idempotent).
4. Register the `before_request` hook that hydrates `g.user`.
5. Register the auth blueprint.
6. Register application routes.

The `g.user` hook (#4) MUST come before any route decorator that calls
`@login_required` / `@roles_required`, otherwise every protected request
sees `g.user is None` and redirects to /login forever.
"""
import os

from flask import Flask, g, redirect, render_template, url_for,request,flash
from auth import auth_bp, csrf, load_current_user, login_required, roles_required
import testdb
import json, sqlite3,snapdiff
from pathlib import Path

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Used only when SNAPLENS_SECRET_KEY is unset (local dev). Set the env var
# in any shared/production deployment.
_DEV_SECRET_KEY = "dev-local-secret-change-me"


def _configure(app: Flask) -> None:
    """Apply security-relevant Flask config in one place."""
    app.config["SECRET_KEY"] = os.environ.get("SNAPLENS_SECRET_KEY", _DEV_SECRET_KEY)
    app.config["SESSION_COOKIE_HTTPONLY"] = True       # JS cannot read the cookie
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # blocks most CSRF via cross-site POSTs

ALLOWED_CONFIG_ROOTS: list[Path] = [
    Path(__file__).resolve().parent / "sample_configs",
    Path("/etc/ssh"),
    Path("/etc/sysctl.d"),
]

def _parse_diff_payload(diff_json_str: str | None) -> dict:
    if not diff_json_str:
        return {"added": [], "modified": [], "removed": [], "lines": [], "sha256": ""}
    try:
        parsed = json.loads(diff_json_str)
        if isinstance(parsed, dict):
            return {
                "added": parsed.get("added") or [],
                "modified": parsed.get("modified") or [],
                "removed": parsed.get("removed") or [],
                "lines": parsed.get("lines") or [],
                "sha256": parsed.get("sha256") or "",
            }
    except (TypeError, ValueError):
        pass
    return {"added": [], "modified": [], "removed": [], "lines": [], "sha256": ""}

# --------------------------------------------------------------------------- #
# Route table
# --------------------------------------------------------------------------- #

# Each entry: (URL rule, endpoint, view function, required roles or None).
# Kept as data so the whole access model is visible in one screen.
#
# Roles: None           → any authenticated user
#        ("engineer",)  → engineers and admins (admin is added by helper)
#        ("admin",)     → admins only


def _register_routes(app: Flask) -> None:
    """Attach every application route to `app`."""

    @app.route("/")
    def index():
        """Send anonymous users to /login, signed-in users to /dashboard."""
        if g.get("user") is None:
            return redirect(url_for("auth.login"))
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "mydashboard.html",
            user=g.user,
            section="General Dashboard",
        )

    @app.route("/engineer/capture")
    @roles_required("engineer", "admin")
    def engineer_capture():
        return render_template(
            "mydashboard.html",
            user=g.user,
            section="Engineer Snapshot Capture Area",
        )

    @app.route("/reviewer/queue")
    @roles_required("reviewer", "admin")
    def reviewer_queue():
        return render_template(
            "mydashboard.html",
            user=g.user,
            section="Reviewer Drift Approval Area",
        )

    @app.route("/admin/users")
    @roles_required("admin")
    def admin_users():
        return render_template(
            "mydashboard.html",
            user=g.user,
            section="Admin User & Audit Control Area",
        )
# -------------------------------------------------------------------------
# app routes for integrating user input forms, snapshot table & audit into it.
# -----------------------------------------------------------------------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        actor = g.user
        host_filter = (request.args.get("host_label") or "").strip() or None
        selected_id_raw = request.args.get("snapshot_id")

        snapshots = testdb.list_snapshots(host_label=host_filter, limit=50)
        selected_snapshot = None

        if selected_id_raw and selected_id_raw.isdigit():
            selected_snapshot = testdb.get_snapshot_by_id(int(selected_id_raw))
        elif snapshots:
            selected_snapshot = snapshots[0]

        selected_diff = _parse_diff_payload(
            selected_snapshot["diff_json"] if selected_snapshot else None
        )

        with testdb.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            audit_logs = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 25"
                ).fetchall()
            ]

        return render_template(
            "mydashboard.html",
            user=actor,
            actor=actor,
            section="General Dashboard",
            snapshots=snapshots,
            selected_snapshot=selected_snapshot,
            selected_diff=selected_diff,
            audit_logs=audit_logs,
            host_filter=host_filter or "",
        )

    @app.route("/snapshots/capture", methods=["POST"])
    @login_required
    @roles_required("engineer", "admin")
    def capture_snapshot_route():
        actor = g.user
        host_label = (request.form.get("host_label") or "").strip()
        snapshot_tag = (request.form.get("snapshot_tag") or "").strip()
        target_path = (request.form.get("target_path") or "").strip()

        if not host_label or not snapshot_tag or not target_path:
            flash("Host label, snapshot tag, and target path are required.", "error")
            return redirect(url_for("dashboard"))

        try:
            result = snapdiff.capture_and_diff_snapshot(
                host_label=host_label,
                snapshot_tag=snapshot_tag,
                target_path=target_path,
                actor=actor,
                allowed_roots=ALLOWED_CONFIG_ROOTS,
                review_status="pending_review",
            )
            flash(
                f"Captured snapshot #{result['id']} ({snapshot_tag}) — "
                f"+{result['added_count']} added, ~{result['modified_count']} modified, "
                f"-{result['removed_count']} removed.",
                "success",
            )
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            flash(f"Snapshot capture blocked or failed: {exc}", "error")

        return redirect(url_for("dashboard", host_label=host_label))

    @app.route("/snapshots/<int:snapshot_id>/review", methods=["POST"])
    @login_required
    @roles_required("reviewer", "admin")
    def review_snapshot_route(snapshot_id: int):
        actor = g.user
        new_status = (request.form.get("review_status") or "").strip()
        review_notes = (request.form.get("review_notes") or "").strip()

        if new_status not in testdb.VALID_REVIEW_STATUSES:
            flash("Invalid review status selected.", "error")
            return redirect(url_for("dashboard", snapshot_id=snapshot_id))

        snap = testdb.get_snapshot_by_id(snapshot_id)
        if not snap:
            flash("Snapshot not found.", "error")
            return redirect(url_for("dashboard"))

        updated = testdb.update_snapshot_review(
            snapshot_id=snapshot_id,
            review_status=new_status,
            reviewed_by=actor.get("id"),
            review_notes=review_notes,
        )

        if updated:
            testdb.log_audit_event(
                actor_id=actor.get("id"),
                actor_username=actor.get("username", "unknown"),
                actor_role=actor.get("role", "unknown"),
                action="SNAPSHOT_REVIEWED",
                target_type="snapshot",
                target_id=str(snapshot_id),
                details=json.dumps(
                    {
                        "host_label": snap["host_label"],
                        "snapshot_tag": snap["snapshot_tag"],
                        "review_status": new_status,
                        "review_notes": review_notes,
                    }
                ),
            )
            flash(f"Snapshot #{snapshot_id} marked as '{new_status}'.", "success")
        else:
            flash("Could not update snapshot review status.", "error")

        return redirect(url_for("dashboard", snapshot_id=snapshot_id))

# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #

def create_app() -> Flask:
    """Build and return the configured Flask app."""
    app = Flask(__name__)
    # 1. Security config first — before anything reads app.config.
    _configure(app)

    # 2. CSRF before any form renders.
    csrf.init_app(app)

    # 3. Idempotent DB bootstrap — safe to run on every start.
    testdb.init_db()
    testdb.seed_default_users()

    # 4. Hydrate g.user on every request. MUST be before blueprint/routes
    #    that depend on it (login_required, roles_required).
    app.before_request(load_current_user)

    # 5. Auth blueprint (login/logout routes).
    app.register_blueprint(auth_bp)

    # 6. Application routes (dashboard, role-gated areas).
    _register_routes(app)

    return app


# Module-level instance so `flask --app app run` works and WSGI servers
# (gunicorn/uwsgi) can import it directly.
app = create_app()


if __name__ == "__main__":
    # debug=False intentionally: the Flask debugger must never be exposed
    # when this is reachable from a browser, even on localhost.
    app.run(host="127.0.0.1", port=5000, debug=False)