"""Registration, sign-in, sign-out and password change."""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from ..extensions import db, limiter
from ..models import Role, User, utcnow
from ..security import audit, hash_password, needs_rehash, safe_next_url, verify_password
from .forms import ChangePasswordForm, LoginForm, RegisterForm

bp = Blueprint("auth", __name__)

LOGIN_FAILED = "Incorrect details, or the account is temporarily locked. Please try again."


def _start_session(user: User) -> None:
    """Begin a fresh session so a pre-login session ID can never be reused."""
    session.clear()
    login_user(user, remember=False)
    session.permanent = True  # enables the idle timeout
    session["login_at"] = utcnow().timestamp()


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        user = db.session.scalar(db.select(User).where(or_(
            User.email == identifier.lower(), User.student_id == identifier.upper(),
        )))
        # Always verify, even for unknown or locked accounts, to keep timing even.
        password_ok = verify_password(user.password_hash if user else None, form.password.data)

        if user is None:
            audit("auth.login", "failed", actor=identifier, detail="unknown account")
        elif user.is_locked:
            audit("auth.login", "locked", user=user, detail="attempt while locked")
        elif not user.active:
            audit("auth.login", "failed", user=user, detail="account disabled")
        elif not password_ok:
            user.failed_logins += 1
            detail = f"wrong password (attempt {user.failed_logins})"
            if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
                user.locked_until = utcnow() + current_app.config["LOCKOUT_PERIOD"]
                user.failed_logins = 0
                detail += " - account locked"
            db.session.commit()
            audit("auth.login", "failed", user=user, detail=detail)
        else:
            user.failed_logins = 0
            user.locked_until = None
            user.last_login_at = utcnow()
            if needs_rehash(user.password_hash):
                user.password_hash = hash_password(form.password.data)
            db.session.commit()
            _start_session(user)
            audit("auth.login", user=user)
            return redirect(safe_next_url(request.args.get("next")) or url_for("main.home"))

        flash(LOGIN_FAILED, "error")

    return render_template("auth/login.html", form=form)


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User(
            email=email,
            full_name=" ".join(form.full_name.data.split()),
            student_id=form.student_id.data.upper(),
            role=Role.STUDENT,  # the role is never taken from the form
            password_hash=hash_password(form.password.data),
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            audit("auth.register", "failed", actor=email, detail="duplicate e-mail or student ID")
            flash("We could not create an account with those details. "
                  "If you already have an account, sign in instead.", "error")
        else:
            audit("auth.register", user=user)
            flash("Your account is ready. Sign in to continue.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user._get_current_object()
    user.rotate_session()  # invalidates this session on the server, on every device
    db.session.commit()
    audit("auth.logout", user=user)
    logout_user()
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/account/security", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def account_security():
    user = current_user._get_current_object()
    form = ChangePasswordForm(user)
    if form.validate_on_submit():
        if not verify_password(user.password_hash, form.current_password.data):
            audit("auth.password_change", "failed", user=user, detail="wrong current password")
            form.current_password.errors.append("That is not your current password.")
        else:
            user.password_hash = hash_password(form.password.data)
            user.password_changed_at = utcnow()
            user.rotate_session()  # signs out every other session
            db.session.commit()
            _start_session(user)
            audit("auth.password_change", user=user)
            flash("Your password has been changed. Other devices have been signed out.", "success")
            return redirect(url_for("auth.account_security"))
    return render_template("auth/security.html", form=form)
