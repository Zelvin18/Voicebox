"""Voicebox application factory."""
import logging
from pathlib import Path

import click
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, logout_user
from flask_wtf.csrf import CSRFError

from config import get_config

from .extensions import csrf, db, limiter, login_manager
from .models import Role, User, utcnow


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is not set. Copy .env.example to .env and add one.")

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.logger.setLevel(logging.INFO)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "info"
    login_manager.session_protection = "basic"

    from .auth.routes import bp as auth_bp
    from .main.routes import bp as main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    _register_session_rules(app)
    _register_security_headers(app)
    _register_error_pages(app)
    _register_cli(app)

    app.jinja_env.globals["Role"] = Role
    return app


@login_manager.user_loader
def load_user(session_id: str) -> User | None:
    user_id, _, nonce = session_id.partition(".")
    if not user_id.isdigit():
        return None
    user = db.session.get(User, int(user_id))
    if user is None or not user.active or not user.session_matches(nonce):
        return None
    return user


def _register_session_rules(app: Flask) -> None:
    @app.before_request
    def enforce_absolute_timeout():
        if not current_user.is_authenticated:
            return None
        started = session.get("login_at", 0)
        limit = app.config["SESSION_ABSOLUTE_LIFETIME"].total_seconds()
        if utcnow().timestamp() - started > limit:
            logout_user()
            session.clear()
            flash("Your session has expired. Please sign in again.", "info")
            return redirect(url_for("auth.login"))
        return None


def _register_security_headers(app: Flask) -> None:
    csp = (
        "default-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )

    @app.after_request
    def set_headers(response):
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response


def _register_error_pages(app: Flask) -> None:
    pages = {
        400: ("Bad request", "The request could not be understood."),
        403: ("Access denied", "You do not have permission to view this page."),
        404: ("Page not found", "The page you are looking for does not exist."),
        413: ("File too large", "The file you tried to send is too large."),
        429: ("Too many attempts", "Please wait a moment and try again."),
        500: ("Something went wrong", "The problem has been logged. Please try again later."),
    }

    def make_handler(code: int):
        def handler(_error):
            if code == 500:
                db.session.rollback()
            title, message = pages[code]
            return render_template("error.html", code=code, title=title, message=message), code
        return handler

    for code in pages:
        app.register_error_handler(code, make_handler(code))

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        return render_template(
            "error.html", code=400, title="Form expired",
            message="For your security this form expired. Go back, refresh the page and try again.",
        ), 400


def _register_cli(app: Flask) -> None:
    from .security import audit, hash_password, password_problem

    @app.cli.command("init-db")
    def init_db():
        """Create the database tables."""
        db.create_all()
        click.echo("Database ready.")

    @app.cli.command("create-user")
    @click.option("--role", type=click.Choice(Role.ALL), required=True)
    @click.option("--email", required=True)
    @click.option("--name", required=True, help="Full name")
    @click.option("--department", default=None)
    @click.password_option()
    def create_user(role, email, name, department, password):
        """Create a staff or administrator account (students register online)."""
        email = email.strip().lower()
        problem = password_problem(password, email, name)
        if problem:
            raise click.ClickException(problem)
        if db.session.scalar(db.select(User).filter_by(email=email)):
            raise click.ClickException("That e-mail address is already in use.")
        user = User(email=email, full_name=name.strip(), role=role, department=department,
                    password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        audit("user.created", target=email, detail=f"role={role} via cli", actor="cli")
        click.echo(f"Created {role} account for {email}.")
