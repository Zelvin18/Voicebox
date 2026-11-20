"""Role-aware home pages. Every query is scoped to what the signed-in user may see."""
from datetime import timedelta

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from ..extensions import db
from ..models import AuditLog, Complaint, Role, Status, User, utcnow
from ..security import roles_required

bp = Blueprint("main", __name__)

PAGE_SIZE = 50
AUDIT_GROUPS = {
    "all": ("All events", None),
    "auth": ("Authentication", "auth."),
    "access": ("Access control", "access."),
    "complaint": ("Complaints", "complaint."),
    "upload": ("Uploads", "upload."),
    "user": ("Users", "user."),
}


def _count(*conditions) -> int:
    return db.session.scalar(db.select(func.count(Complaint.id)).where(*conditions)) or 0


@bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))
    return redirect(url_for("auth.login"))


@bp.route("/home")
@login_required
def home():
    user = current_user
    filters = {"all": "All", "open": "Open", "resolved": "Resolved"}

    # The scope is the access rule: it is applied to every count and every row.
    if user.role == Role.STUDENT:
        scope = [Complaint.student_id == user.id]
        title, subtitle = "My complaints", f"Welcome, {user.first_name}."
        stats = [
            ("Submitted", _count(*scope, Complaint.status == Status.SUBMITTED), "Waiting for a response", "blue"),
            ("In progress", _count(*scope, Complaint.status == Status.IN_PROGRESS), "Staff are working on it", "orange"),
            ("Awaiting you", _count(*scope, Complaint.status == Status.AWAITING_STUDENT), "Staff need a reply", "purple"),
            ("Resolved", _count(*scope, Complaint.status == Status.RESOLVED), "Closed cases", "green"),
        ]
        empty = ("No complaints yet", "When you submit a complaint it will appear here, "
                 "with its status and who is handling it.")
    elif user.role == Role.STAFF:
        scope = [Complaint.assigned_to_id == user.id]
        title, subtitle = "My cases", "Cases an administrator has assigned to you."
        stats = [
            ("New", _count(*scope, Complaint.status == Status.SUBMITTED), "Not started", "blue"),
            ("In progress", _count(*scope, Complaint.status == Status.IN_PROGRESS), "You are working on these", "orange"),
            ("Awaiting student", _count(*scope, Complaint.status == Status.AWAITING_STUDENT), "Paused", "purple"),
            ("Resolved", _count(*scope, Complaint.status == Status.RESOLVED), "Closed cases", "green"),
        ]
        empty = ("No cases here", "Cases an administrator assigns to you will appear here.")
    else:
        scope = []
        filters = {"all": "All", "unassigned": "Unassigned", "open": "Open", "resolved": "Resolved"}
        unassigned = _count(Complaint.assigned_to_id.is_(None), Complaint.status.in_(Status.OPEN))
        title = "All complaints"
        subtitle = (f"{unassigned} complaint{'' if unassigned == 1 else 's'} waiting to be assigned."
                    if unassigned else "Every complaint has an owner.")
        stats = [
            ("Unassigned", unassigned, "Waiting for you", "red"),
            ("Open", _count(Complaint.status.in_(Status.OPEN)), "Across all staff", "orange"),
            ("Resolved", _count(Complaint.status == Status.RESOLVED), "Closed cases", "green"),
            ("Users", db.session.scalar(db.select(func.count(User.id))) or 0, "Registered accounts", "blue"),
        ]
        empty = ("Nothing here", "Complaints from students will appear here, ready to assign.")

    active = request.args.get("show", "all")
    if active not in filters:
        active = "all"
    conditions = list(scope)
    if active == "open":
        conditions.append(Complaint.status.in_(Status.OPEN))
    elif active == "resolved":
        conditions.append(Complaint.status.in_((Status.RESOLVED, Status.WITHDRAWN)))
    elif active == "unassigned":
        conditions += [Complaint.assigned_to_id.is_(None), Complaint.status.in_(Status.OPEN)]

    complaints = db.session.scalars(
        db.select(Complaint).where(*conditions).order_by(Complaint.updated_at.desc()).limit(200)
    ).all()
    return render_template("home.html", title=title, subtitle=subtitle, stats=stats, empty=empty,
                           complaints=complaints, filters=filters, active=active)


@bp.route("/admin/users")
@roles_required(Role.ADMIN)
def admin_users():
    users = db.session.scalars(db.select(User).order_by(User.created_at.desc()).limit(200)).all()
    return render_template("admin/users.html", users=users)


@bp.route("/admin/audit")
@roles_required(Role.ADMIN)
def admin_audit():
    group = request.args.get("group", "all")
    if group not in AUDIT_GROUPS:
        group = "all"
    page = max(request.args.get("page", 1, type=int) or 1, 1)

    query = db.select(AuditLog)
    prefix = AUDIT_GROUPS[group][1]
    if prefix:
        query = query.where(AuditLog.event.startswith(prefix, autoescape=True))
    rows = db.session.scalars(
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(PAGE_SIZE + 1).offset((page - 1) * PAGE_SIZE)
    ).all()

    now = utcnow()
    day_ago = now - timedelta(hours=24)

    def events(*conditions) -> int:
        return db.session.scalar(db.select(func.count(AuditLog.id)).where(*conditions)) or 0

    stats = [
        ("Sign-ins", events(AuditLog.event == "auth.login", AuditLog.outcome == "success",
                            AuditLog.created_at >= day_ago), "Last 24 hours", "green"),
        ("Failed sign-ins", events(AuditLog.event == "auth.login", AuditLog.outcome != "success",
                                   AuditLog.created_at >= day_ago), "Last 24 hours", "orange"),
        ("Access denied", events(AuditLog.event == "access.denied", AuditLog.created_at >= day_ago),
         "Blocked by access control", "red"),
        ("Accounts locked", db.session.scalar(db.select(func.count(User.id)).where(User.locked_until > now)) or 0,
         "Right now", "purple"),
    ]
    return render_template("admin/audit.html", rows=rows[:PAGE_SIZE], has_next=len(rows) > PAGE_SIZE,
                           page=page, group=group, groups=AUDIT_GROUPS, stats=stats)
