"""
auth.py — authentication blueprint for Snaplens.

Routes
------
GET/POST /login   : render and process the login form
POST     /logout  : clear the session and audit the event

Decorators
----------
login_required   : redirect anonymous users to /login
roles_required   : allow only the listed roles (audits + redirects otherwise)

Wiring (in app.py)
------------------
1. csrf.init_app(app)                    # before any form renders
2. app.register_blueprint(auth_bp)
3. app.before_request(load_current_user) # populates g.user each request
4. An endpoint named "dashboard" must exist — url_for("dashboard") is used
   by login success and by roles_required.
"""
from functools import wraps

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

import testdb

# Audit action names — centralised so call sites can't silently diverge.
ACTION_LOGIN_SUCCESS = "LOGIN_SUCCESS"
ACTION_LOGIN_FAILED  = "LOGIN_FAILED"
ACTION_LOGOUT        = "LOGOUT"
ACTION_ACCESS_DENIED = "ACCESS_DENIED"

csrf = CSRFProtect()
auth_bp = Blueprint("auth", __name__)


# --------------------------------------------------------------------------- #
# Forms
# --------------------------------------------------------------------------- #

class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(message="Username is required."), Length(min=2, max=64)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")],
    )
    submit = SubmitField("Sign In")


# --------------------------------------------------------------------------- #
# Request hook & decorators
# --------------------------------------------------------------------------- #

def load_current_user() -> None:
    """
    before_request hook: populate `g.user` from the session.

    A stale or deactivated user is cleared from the session so the
    next request starts anonymous.
    """
    user_id = session.get("user_id")
    g.user = None
    if user_id is None:
        return

    user = testdb.get_user_by_id(int(user_id))
    if user is not None and user["is_active"] == 1:
        g.user = user
    else:
        session.clear()


def login_required(view_func):
    """Redirect anonymous users to /login, remembering where they were headed."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            flash("Please sign in to access Snaplens.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def _audit_access_denied(user, required_roles: tuple[str, ...]) -> None:
    """Record an ACCESS_DENIED event for the current request."""
    testdb.log_audit_event(
        actor_id=user["id"],
        actor_username=user["username"],
        actor_role=user["role"],
        action=ACTION_ACCESS_DENIED,
        target_type="route",
        target_id=request.path,
        details=f"Attempted access requiring roles {list(required_roles)}",
    )


def roles_required(*allowed_roles: str):
    """Allow the view only if g.user.role is one of `allowed_roles`."""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in allowed_roles:
                _audit_access_denied(g.user, allowed_roles)
                flash("You do not have permission to access that page.", "error")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


# --------------------------------------------------------------------------- #
# Login helpers
# --------------------------------------------------------------------------- #

def _is_safe_redirect(target: str) -> bool:
    """Allow only same-origin relative paths (reject '//evil.com' open redirects)."""
    return target.startswith("/") and not target.startswith("//")


def _record_login_success(user) -> None:
    """Rotate the session and write a LOGIN_SUCCESS audit entry."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    # username/role deliberately not stored — g.user is reloaded from the
    # DB on every request, so the session can never hold stale role data.

    testdb.log_audit_event(
        actor_id=user["id"],
        actor_username=user["username"],
        actor_role=user["role"],
        action=ACTION_LOGIN_SUCCESS,
        target_type="session",
        target_id=str(user["id"]),
        details="Authenticated via login form",
    )
    flash(f"Signed in as {user['username']} ({user['role']}).", "success")


def _record_login_failure(username: str) -> None:
    """Write a LOGIN_FAILED audit entry and show a generic error."""
    testdb.log_audit_event(
        actor_id=None,
        actor_username=username,
        actor_role="anonymous",
        action=ACTION_LOGIN_FAILED,
        target_type="session",
        target_id=username,
        details="Invalid credentials or inactive account",
    )
    flash("Invalid username or password.", "error")


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if g.get("user") is not None:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        user = testdb.verify_user_credentials(username, form.password.data)

        if user is not None:
            _record_login_success(user)
            next_url = request.args.get("next", "")
            return redirect(next_url if _is_safe_redirect(next_url) else url_for("dashboard"))

        _record_login_failure(username)

    return render_template("login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    # Snapshot identity before clearing the session so we can audit it.
    actor = {
        "id": g.user["id"],
        "username": g.user["username"],
        "role": g.user["role"],
    }
    session.clear()

    testdb.log_audit_event(
        actor_id=actor["id"],
        actor_username=actor["username"],
        actor_role=actor["role"],
        action=ACTION_LOGOUT,
        target_type="session",
        target_id=str(actor["id"]),
        details="User signed out",
    )
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))