"""Password hashing, password policy, audit logging and access-control helpers."""
from functools import wraps
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import abort, current_app, has_request_context, request
from flask_login import current_user, login_required

from .extensions import db
from .models import AuditLog

_hasher = PasswordHasher()  # Argon2id with the library's recommended parameters
_DUMMY_HASH = _hasher.hash("voicebox-timing-equaliser")

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
_COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "cavendish123", "cavendish2026",
    "voicebox1234", "letmein12345", "iloveyou1234", "administrator", "welcome12345",
    "passwordpassword", "111111111111", "000000000000", "abcdefghijkl",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Check a password. Always does the hashing work, even when there is no
    such user, so response time does not reveal which accounts exist."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problem(password: str, *related: str) -> str | None:
    """Return why a password is not acceptable, or None if it is fine.
    Length matters more than symbol rules (NIST SP 800-63B)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Use at most {MAX_PASSWORD_LENGTH} characters."
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(lowered)) < 5:
        return "That password is too easy to guess."
    for value in related:
        token = (value or "").lower().split("@")[0]
        if len(token) >= 4 and token in lowered:
            return "Do not include your name, e-mail or student ID in the password."
    return None


def _clean(value, limit: int) -> str | None:
    """Strip line breaks so user input cannot forge log lines."""
    if value is None:
        return None
    return " ".join(str(value).split())[:limit]


def audit(event: str, outcome: str = "success", *, target=None, detail=None, user=None, actor=None) -> None:
    """Write one security event to the audit log and the application log.
    Never pass passwords, tokens or session IDs in here."""
    if user is None and has_request_context() and current_user.is_authenticated:
        user = current_user
    entry = AuditLog(
        user_id=user.id if user else None,
        actor=_clean(user.email if user else actor, 254),
        role=user.role if user else None,
        event=event,
        outcome=outcome,
        target=_clean(target, 200),
        detail=_clean(detail, 300),
        ip=request.remote_addr if has_request_context() else None,
        user_agent=_clean(request.user_agent.string, 200) if has_request_context() else "cli",
    )
    db.session.add(entry)
    db.session.commit()
    log = current_app.logger.info if outcome == "success" else current_app.logger.warning
    log("audit event=%s outcome=%s actor=%s target=%s ip=%s",
        event, outcome, entry.actor, entry.target, entry.ip)


def roles_required(*roles: str):
    """Allow a view only for signed-in users holding one of the given roles."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                audit("access.denied", "denied", target=request.path, detail="role not permitted")
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def safe_next_url(target: str | None) -> str | None:
    """Accept only local paths as a post-login destination (no open redirect)."""
    if not target:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    return target
