"""Role-aware home pages. Every query is scoped to what the signed-in user may see."""
from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from ..extensions import db
from ..models import Complaint, Role, Status, User
from ..security import roles_required

bp = Blueprint("main", __name__)


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
    if user.role == Role.STUDENT:
        mine = Complaint.student_id == user.id
        title = "My complaints"
        stats = [
            ("Submitted", _count(mine, Complaint.status == Status.SUBMITTED), "Waiting to be assigned", "blue"),
            ("In progress", _count(mine, Complaint.status == Status.IN_PROGRESS), "Staff are working on it", "orange"),
            ("Awaiting you", _count(mine, Complaint.status == Status.AWAITING_STUDENT), "Staff need a reply", "purple"),
            ("Resolved", _count(mine, Complaint.status == Status.RESOLVED), "Closed cases", "green"),
        ]
        empty = ("No complaints yet", "When you submit a complaint it will appear here, "
                 "with its status and who is handling it.")
    elif user.role == Role.STAFF:
        mine = Complaint.assigned_to_id == user.id
        title = "My cases"
        stats = [
            ("Assigned", _count(mine, Complaint.status == Status.SUBMITTED), "Not started", "blue"),
            ("In progress", _count(mine, Complaint.status == Status.IN_PROGRESS), "You are working on these", "orange"),
            ("Awaiting student", _count(mine, Complaint.status == Status.AWAITING_STUDENT), "Paused", "purple"),
            ("Resolved", _count(mine, Complaint.status == Status.RESOLVED), "Closed cases", "green"),
        ]
        empty = ("No cases assigned", "Cases an administrator assigns to you will appear here.")
    else:
        title = "All complaints"
        stats = [
            ("Unassigned", _count(Complaint.assigned_to_id.is_(None), Complaint.status.in_(Status.OPEN)),
             "Waiting for you", "red"),
            ("Open", _count(Complaint.status.in_(Status.OPEN)), "Across all staff", "orange"),
            ("Resolved", _count(Complaint.status == Status.RESOLVED), "Closed cases", "green"),
            ("Users", db.session.scalar(db.select(func.count(User.id))) or 0, "Registered accounts", "blue"),
        ]
        empty = ("No complaints yet", "New complaints from students will appear here, ready to assign.")
    return render_template("home.html", title=title, stats=stats, empty=empty)


@bp.route("/admin/users")
@roles_required(Role.ADMIN)
def admin_users():
    users = db.session.scalars(db.select(User).order_by(User.created_at.desc()).limit(200)).all()
    return render_template("admin/users.html", users=users)
