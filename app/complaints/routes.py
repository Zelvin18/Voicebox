"""Complaint workflow. Every route re-checks, on the server, that the signed-in
user is allowed to see or change the complaint in question."""
import re

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   send_from_directory, url_for)
from flask_login import current_user, login_required
from sqlalchemy import func

from ..extensions import db, limiter
from ..models import Attachment, AuditLog, Complaint, Message, Role, Status, User, utcnow
from ..security import audit, roles_required
from ..uploads import UploadError, save_upload
from .forms import AssignForm, ComplaintForm, ReplyForm, StatusForm

bp = Blueprint("complaints", __name__)

REFERENCE = re.compile(r"^VB-[2-9A-HJ-NP-Z]{8}$")
TIMELINE = {
    "complaint.created": "Submitted",
    "complaint.assigned": "Assigned to {detail}",
    "complaint.status": "{detail}",
    "complaint.withdrawn": "Withdrawn by the student",
    "complaint.reopened": "Reopened by the student",
}


def _user_key() -> str:
    return f"user:{current_user.id}"


# ---------- permissions ----------

def can_view(user: User, complaint: Complaint) -> bool:
    if user.role == Role.ADMIN:
        return True
    if user.role == Role.STUDENT:
        return complaint.student_id == user.id
    if user.role == Role.STAFF:
        return complaint.assigned_to_id == user.id
    return False


def permissions(user: User, complaint: Complaint) -> dict:
    owner = user.role == Role.STUDENT and complaint.student_id == user.id
    handler = user.role == Role.STAFF and complaint.assigned_to_id == user.id
    return {
        "reply": (owner or handler) and complaint.is_open,
        "internal_note": handler and complaint.is_open,
        "status": handler and complaint.is_open,
        "assign": user.role == Role.ADMIN and complaint.is_open,
        "withdraw": owner and complaint.is_open,
        "reopen": owner and complaint.status == Status.RESOLVED,
    }


def load_complaint(reference: str) -> Complaint:
    """Fetch a complaint the current user may see. Anything else is a 404, so
    the response never confirms that someone else's complaint exists."""
    complaint = None
    if REFERENCE.match(reference):
        complaint = db.session.scalar(db.select(Complaint).filter_by(reference=reference))
    if complaint is None:
        abort(404)
    if not can_view(current_user, complaint):
        audit("access.denied", "denied", target=reference, detail="tried to open a complaint they may not see")
        abort(404)
    return complaint


def require(complaint: Complaint, action: str) -> None:
    if not permissions(current_user, complaint)[action]:
        audit("access.denied", "denied", target=complaint.reference, detail=f"action not permitted: {action}")
        abort(403)


def _set_status(complaint: Complaint, status: str) -> None:
    complaint.status = status
    complaint.updated_at = utcnow()
    db.session.commit()
    audit("complaint.status", target=complaint.reference, detail=Status.LABELS[status])


def _back(complaint: Complaint):
    return redirect(url_for("complaints.detail", reference=complaint.reference))


def _first_error(form) -> str:
    for errors in form.errors.values():
        return errors[0]
    return "That could not be saved. Please try again."


def _staff_choices() -> list[tuple[int, str]]:
    open_cases = dict(db.session.execute(
        db.select(Complaint.assigned_to_id, func.count(Complaint.id))
        .where(Complaint.status.in_(Status.OPEN)).group_by(Complaint.assigned_to_id)
    ).all())
    staff = db.session.scalars(
        db.select(User).where(User.role == Role.STAFF, User.active.is_(True)).order_by(User.full_name)
    )
    return [(s.id, f"{s.full_name} · {s.department or 'Staff'} · {open_cases.get(s.id, 0)} open") for s in staff]


# ---------- student: create ----------

@bp.route("/complaints/new", methods=["GET", "POST"])
@roles_required(Role.STUDENT)
@limiter.limit("20 per hour", methods=["POST"], key_func=_user_key)
def new():
    form = ComplaintForm()
    if form.validate_on_submit():
        upload = None
        file = form.evidence.data
        if file and file.filename:
            try:
                upload = save_upload(file)
            except UploadError as error:
                audit("upload.rejected", "rejected", detail=f"{error} ({file.filename})")
                form.evidence.errors = [str(error)]
        if not form.evidence.errors:
            complaint = Complaint(
                student_id=current_user.id,  # the owner always comes from the session
                category=form.category.data, subject=form.subject.data, body=form.body.data,
            )
            if upload:
                complaint.attachments.append(Attachment(uploader_id=current_user.id, **upload))
            db.session.add(complaint)
            db.session.commit()
            audit("complaint.created", target=complaint.reference, detail=complaint.category)
            if upload:
                audit("upload.accepted", target=complaint.reference,
                      detail=f"{upload['mime_type']}, {upload['size']} bytes")
            flash(f"Complaint {complaint.reference} submitted. We will keep you updated here.", "success")
            return _back(complaint)
    return render_template("complaints/new.html", form=form)


# ---------- everyone: view ----------

@bp.route("/complaints/<reference>")
@login_required
def detail(reference):
    complaint = load_complaint(reference)
    can = permissions(current_user, complaint)

    messages = complaint.messages
    if current_user.role == Role.STUDENT:
        messages = [m for m in messages if not m.internal]  # staff notes stay private

    entries = db.session.scalars(
        db.select(AuditLog).where(AuditLog.target == complaint.reference, AuditLog.outcome == "success",
                                  AuditLog.event.in_(TIMELINE)).order_by(AuditLog.created_at)
    )
    timeline = [(TIMELINE[e.event].format(detail=e.detail or ""), e.created_at) for e in entries]

    assign_form = None
    if can["assign"]:
        assign_form = AssignForm(staff_id=complaint.assigned_to_id)
        assign_form.staff_id.choices = _staff_choices()

    return render_template("complaints/detail.html", complaint=complaint, messages=messages, can=can,
                           timeline=timeline, reply_form=ReplyForm(), assign_form=assign_form)


@bp.route("/attachments/<int:attachment_id>")
@login_required
def download(attachment_id):
    attachment = db.session.get(Attachment, attachment_id)
    if attachment is None:
        abort(404)
    if not can_view(current_user, attachment.complaint):
        audit("access.denied", "denied", target=attachment.complaint.reference,
              detail="tried to download an attachment they may not see")
        abort(404)
    audit("attachment.download", target=attachment.complaint.reference, detail=attachment.original_name)
    response = send_from_directory(
        current_app.config["UPLOAD_FOLDER"], attachment.stored_name, mimetype=attachment.mime_type,
        as_attachment=True, download_name=attachment.original_name, max_age=0,
    )
    # Even if a browser opens the file, it may not run scripts or load anything.
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


# ---------- student and staff: conversation ----------

@bp.route("/complaints/<reference>/reply", methods=["POST"])
@login_required
@limiter.limit("60 per hour", key_func=_user_key)
def reply(reference):
    complaint = load_complaint(reference)
    require(complaint, "reply")
    form = ReplyForm()
    if not form.validate_on_submit():
        flash(_first_error(form), "error")
        return _back(complaint)

    internal = bool(form.internal.data) and permissions(current_user, complaint)["internal_note"]
    db.session.add(Message(complaint=complaint, author_id=current_user.id, body=form.body.data, internal=internal))
    complaint.updated_at = utcnow()
    db.session.commit()
    audit("complaint.note" if internal else "complaint.reply", target=complaint.reference)

    if not internal:
        if current_user.role == Role.STAFF and complaint.status == Status.SUBMITTED:
            _set_status(complaint, Status.IN_PROGRESS)
        elif current_user.role == Role.STUDENT and complaint.status == Status.AWAITING_STUDENT:
            _set_status(complaint, Status.IN_PROGRESS)
    return _back(complaint)


@bp.route("/complaints/<reference>/withdraw", methods=["POST"])
@login_required
def withdraw(reference):
    complaint = load_complaint(reference)
    require(complaint, "withdraw")
    complaint.status = Status.WITHDRAWN
    complaint.updated_at = utcnow()
    db.session.commit()
    audit("complaint.withdrawn", target=complaint.reference)
    flash("Your complaint has been withdrawn.", "success")
    return _back(complaint)


@bp.route("/complaints/<reference>/reopen", methods=["POST"])
@login_required
def reopen(reference):
    complaint = load_complaint(reference)
    require(complaint, "reopen")
    complaint.status = Status.IN_PROGRESS
    complaint.updated_at = utcnow()
    db.session.commit()
    audit("complaint.reopened", target=complaint.reference)
    flash("Your complaint has been reopened.", "success")
    return _back(complaint)


# ---------- staff: status ----------

@bp.route("/complaints/<reference>/status", methods=["POST"])
@login_required
def set_status(reference):
    complaint = load_complaint(reference)
    require(complaint, "status")
    form = StatusForm()
    if not form.validate_on_submit():
        abort(400)
    if form.status.data != complaint.status:
        _set_status(complaint, form.status.data)
        flash(f"Status changed to {complaint.status_label}.", "success")
    return _back(complaint)


# ---------- administrator: assignment ----------

@bp.route("/complaints/<reference>/assign", methods=["POST"])
@roles_required(Role.ADMIN)
def assign(reference):
    complaint = load_complaint(reference)
    require(complaint, "assign")
    form = AssignForm()
    form.staff_id.choices = _staff_choices()  # only active staff can be chosen
    if not form.validate_on_submit():
        audit("complaint.assigned", "failed", target=complaint.reference, detail="invalid assignee")
        flash("Choose a member of staff to assign this complaint to.", "error")
        return _back(complaint)

    staff = db.session.get(User, form.staff_id.data)
    complaint.assigned_to = staff
    complaint.updated_at = utcnow()
    db.session.commit()
    audit("complaint.assigned", target=complaint.reference, detail=staff.full_name)
    flash(f"{complaint.reference} assigned to {staff.full_name}.", "success")
    return _back(complaint)
