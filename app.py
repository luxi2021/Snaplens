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

from flask import Flask, g, redirect, render_template, url_for

from auth import auth_bp, csrf, load_current_user, login_required, roles_required
import testdb


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