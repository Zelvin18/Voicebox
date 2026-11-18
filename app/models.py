"""Database models. All access goes through the ORM, so queries are parameterised."""
import hmac
import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import event

from .extensions import db


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite does not keep time zones)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _nonce() -> str:
    return secrets.token_hex(16)


def _reference() -> str:
    """Public complaint reference. Random, so it cannot be guessed or counted."""
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    return "VB-" + "".join(secrets.choice(alphabet) for _ in range(8))


class Role:
    STUDENT = "student"
    STAFF = "staff"
    ADMIN = "admin"
    ALL = (STUDENT, STAFF, ADMIN)
    LABELS = {STUDENT: "Student", STAFF: "Staff", ADMIN: "Administrator"}


class Status:
    SUBMITTED = "submitted"
    IN_PROGRESS = "in_progress"
    AWAITING_STUDENT = "awaiting_student"
    RESOLVED = "resolved"
    WITHDRAWN = "withdrawn"
    ALL = (SUBMITTED, IN_PROGRESS, AWAITING_STUDENT, RESOLVED, WITHDRAWN)
    OPEN = (SUBMITTED, IN_PROGRESS, AWAITING_STUDENT)


CATEGORIES = ("Academic", "Finance", "IT & Facilities", "Administration", "Welfare", "Other")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    student_id = db.Column(db.String(20), unique=True, index=True)
    department = db.Column(db.String(80))
    role = db.Column(db.String(20), nullable=False, default=Role.STUDENT)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)

    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    # Part of the session identity: changing it signs the user out everywhere.
    session_nonce = db.Column(db.String(32), nullable=False, default=_nonce)

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        db.CheckConstraint("role IN ('student', 'staff', 'admin')", name="ck_users_role"),
    )

    @property
    def is_active(self) -> bool:
        return self.active

    def get_id(self) -> str:
        return f"{self.id}.{self.session_nonce}"

    def session_matches(self, nonce: str) -> bool:
        return hmac.compare_digest(self.session_nonce, nonce)

    def rotate_session(self) -> None:
        self.session_nonce = _nonce()

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()

    @property
    def role_label(self) -> str:
        return Role.LABELS.get(self.role, self.role)

    @property
    def initials(self) -> str:
        parts = self.full_name.split()
        return (parts[0][:1] + (parts[-1][:1] if len(parts) > 1 else "")).upper()

    @property
    def first_name(self) -> str:
        return self.full_name.split()[0]


class Complaint(db.Model):
    __tablename__ = "complaints"

    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(12), unique=True, nullable=False, index=True, default=_reference)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    category = db.Column(db.String(40), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default=Status.SUBMITTED, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    student = db.relationship("User", foreign_keys=[student_id], backref="complaints")
    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id], backref="cases")
    messages = db.relationship(
        "Message", backref="complaint", order_by="Message.created_at", cascade="all, delete-orphan"
    )
    attachments = db.relationship("Attachment", backref="complaint", cascade="all, delete-orphan")


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey("complaints.id"), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    internal = db.Column(db.Boolean, nullable=False, default=False)  # staff-only note
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    author = db.relationship("User")


class Attachment(db.Model):
    __tablename__ = "attachments"

    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey("complaints.id"), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(64), unique=True, nullable=False)  # random, never user-supplied
    mime_type = db.Column(db.String(80), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class AuditLog(db.Model):
    """Security log: who did what, when, from where, and whether it worked."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    actor = db.Column(db.String(254))  # e-mail or the identifier that was tried
    role = db.Column(db.String(20))
    event = db.Column(db.String(60), nullable=False, index=True)
    outcome = db.Column(db.String(20), nullable=False)
    target = db.Column(db.String(200))
    detail = db.Column(db.String(300))
    ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def _audit_log_is_append_only(*_):
    raise RuntimeError("Audit log entries cannot be changed or deleted.")
