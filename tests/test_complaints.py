"""Complaint workflow, access-control and upload tests (the manual attacks, automated)."""
import io
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Attachment, AuditLog, Complaint, Message, Role, Status, User
from tests.conftest import login

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PDF = b"%PDF-1.7\n" + b"\x00" * 64
COMPLAINT = {
    "category": "IT & Facilities",
    "subject": "Library Wi-Fi keeps dropping",
    "body": "The Wi-Fi in the main library disconnected three times during my online test.",
}


@pytest.fixture
def people(make_user):
    return {
        "alice": make_user(email="alice@example.test", student_id="CU-2024-00001", name="Alice Student"),
        "bob": make_user(email="bob@example.test", student_id="CU-2024-00002", name="Bob Student"),
        "staff": make_user(email="staff@example.test", role=Role.STAFF, name="Sam Staff"),
        "other_staff": make_user(email="staff2@example.test", role=Role.STAFF, name="Olive Other"),
        "admin": make_user(email="admin@example.test", role=Role.ADMIN, name="Ada Admin"),
    }


def as_user(client, email):
    client.post("/logout")
    assert login(client, identifier=email).status_code == 302


def submit(client, **overrides):
    return client.post("/complaints/new", data={**COMPLAINT, **overrides}, content_type="multipart/form-data")


def make_complaint(client, email="alice@example.test", **overrides) -> Complaint:
    as_user(client, email)
    assert submit(client, **overrides).status_code == 302
    return db.session.scalar(db.select(Complaint).order_by(Complaint.id.desc()))


def assign(client, complaint, staff):
    as_user(client, "admin@example.test")
    return client.post(f"/complaints/{complaint.reference}/assign", data={"staff_id": staff.id})


def denied():
    return db.session.scalars(db.select(AuditLog).filter_by(event="access.denied")).all()


def count(model) -> int:
    return db.session.scalar(db.select(db.func.count(model.id)))


# ---------- the workflow ----------

def test_full_workflow(client, people):
    complaint = make_complaint(client)
    assert complaint.status == Status.SUBMITTED
    assert complaint.student_id == people["alice"].id
    assert complaint.reference.startswith("VB-") and len(complaint.reference) == 11

    assert assign(client, complaint, people["staff"]).status_code == 302
    assert complaint.assigned_to_id == people["staff"].id

    as_user(client, "staff@example.test")
    client.post(f"/complaints/{complaint.reference}/reply", data={"body": "We are looking into it."})
    assert complaint.status == Status.IN_PROGRESS
    client.post(f"/complaints/{complaint.reference}/status", data={"status": Status.AWAITING_STUDENT})

    as_user(client, "alice@example.test")
    client.post(f"/complaints/{complaint.reference}/reply", data={"body": "It was on 12 November."})
    assert complaint.status == Status.IN_PROGRESS

    as_user(client, "staff@example.test")
    client.post(f"/complaints/{complaint.reference}/status", data={"status": Status.RESOLVED})
    assert complaint.status == Status.RESOLVED

    as_user(client, "alice@example.test")
    assert client.post(f"/complaints/{complaint.reference}/reply", data={"body": "Thanks"}).status_code == 403
    client.post(f"/complaints/{complaint.reference}/reopen")
    assert complaint.status == Status.IN_PROGRESS

    events = [e.event for e in db.session.scalars(db.select(AuditLog).filter_by(target=complaint.reference))]
    for expected in ("complaint.created", "complaint.assigned", "complaint.reply", "complaint.status",
                     "complaint.reopened"):
        assert expected in events


def test_complaint_owner_comes_from_session_not_form(client, people):
    complaint = make_complaint(client, student_id=str(people["bob"].id), status="resolved",
                               assigned_to_id=str(people["staff"].id))
    assert complaint.student_id == people["alice"].id
    assert complaint.status == Status.SUBMITTED
    assert complaint.assigned_to_id is None


# ---------- broken access control (IDOR) ----------

def test_student_cannot_see_another_students_complaint(client, people):
    complaint = make_complaint(client, "alice@example.test")
    as_user(client, "bob@example.test")

    assert client.get(f"/complaints/{complaint.reference}").status_code == 404
    assert complaint.subject.encode() not in client.get("/home").data
    for action in ("reply", "withdraw", "reopen", "status", "assign"):
        response = client.post(f"/complaints/{complaint.reference}/{action}", data={"body": "hi"})
        assert response.status_code in (403, 404)
    assert complaint.status == Status.SUBMITTED
    assert count(Message) == 0
    assert len(denied()) >= 5


def test_unknown_and_foreign_complaints_look_the_same(client, people):
    complaint = make_complaint(client, "alice@example.test")
    as_user(client, "bob@example.test")
    foreign = client.get(f"/complaints/{complaint.reference}")
    missing = client.get("/complaints/VB-ZZZZZZZZ")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.data == missing.data


def test_staff_see_only_cases_assigned_to_them(client, people):
    complaint = make_complaint(client)
    as_user(client, "staff@example.test")
    assert client.get(f"/complaints/{complaint.reference}").status_code == 404

    assign(client, complaint, people["staff"])
    as_user(client, "staff@example.test")
    assert client.get(f"/complaints/{complaint.reference}").status_code == 200
    assert complaint.subject.encode() in client.get("/home").data

    as_user(client, "staff2@example.test")
    assert client.get(f"/complaints/{complaint.reference}").status_code == 404
    assert complaint.subject.encode() not in client.get("/home").data
    response = client.post(f"/complaints/{complaint.reference}/status", data={"status": Status.RESOLVED})
    assert response.status_code == 404
    assert complaint.status == Status.SUBMITTED


def test_only_admin_can_assign(client, people):
    complaint = make_complaint(client)
    for email in ("alice@example.test", "staff@example.test"):
        as_user(client, email)
        response = client.post(f"/complaints/{complaint.reference}/assign", data={"staff_id": people["staff"].id})
        assert response.status_code == 403
    assert complaint.assigned_to_id is None


def test_admin_can_only_assign_to_staff(client, people):
    complaint = make_complaint(client)
    for target in ("bob", "admin"):
        assign(client, complaint, people[target])
        assert complaint.assigned_to_id is None
    assign(client, complaint, people["staff"])
    assert complaint.assigned_to_id == people["staff"].id


def test_student_cannot_change_status(client, people):
    complaint = make_complaint(client)
    response = client.post(f"/complaints/{complaint.reference}/status", data={"status": Status.RESOLVED})
    assert response.status_code == 403
    assert complaint.status == Status.SUBMITTED


def test_staff_cannot_set_arbitrary_status(client, people):
    complaint = make_complaint(client)
    assign(client, complaint, people["staff"])
    as_user(client, "staff@example.test")
    response = client.post(f"/complaints/{complaint.reference}/status", data={"status": "withdrawn"})
    assert response.status_code == 400
    assert complaint.status == Status.SUBMITTED


def test_only_students_can_create_complaints(client, people):
    for email in ("staff@example.test", "admin@example.test"):
        as_user(client, email)
        assert client.get("/complaints/new").status_code == 403
        assert submit(client).status_code == 403
    assert count(Complaint) == 0


def test_internal_notes_are_hidden_from_students(client, people):
    complaint = make_complaint(client)
    assign(client, complaint, people["staff"])
    as_user(client, "staff@example.test")
    client.post(f"/complaints/{complaint.reference}/reply", data={"body": "SECRET-STAFF-NOTE", "internal": "y"})
    assert b"SECRET-STAFF-NOTE" in client.get(f"/complaints/{complaint.reference}").data

    as_user(client, "alice@example.test")
    assert b"SECRET-STAFF-NOTE" not in client.get(f"/complaints/{complaint.reference}").data
    # A student ticking the box does not make a hidden note.
    client.post(f"/complaints/{complaint.reference}/reply", data={"body": "Visible reply", "internal": "y"})
    assert db.session.scalar(db.select(Message).filter_by(body="Visible reply")).internal is False


def test_audit_log_is_admin_only(client, people):
    for email in ("alice@example.test", "staff@example.test"):
        as_user(client, email)
        assert client.get("/admin/audit").status_code == 403
    as_user(client, "admin@example.test")
    response = client.get("/admin/audit?group=access")
    assert response.status_code == 200
    assert b"access.denied" in response.data


def test_anonymous_users_are_sent_to_login(client, people):
    complaint = make_complaint(client)
    client.post("/logout")
    for path in ("/complaints/new", f"/complaints/{complaint.reference}", "/attachments/1", "/admin/audit"):
        assert client.get(path).status_code == 302
    assert client.post(f"/complaints/{complaint.reference}/reply", data={"body": "x"}).status_code == 302


# ---------- injection ----------

@pytest.mark.parametrize("payload", ["' OR '1'='1", "admin@example.test' --", "x'; DROP TABLE users; --"])
def test_sql_injection_in_login_fails(client, people, payload):
    assert login(client, identifier=payload, password=payload).status_code == 200
    assert client.get("/home").status_code == 302
    assert count(User) == 5


def test_sql_injection_in_complaint_is_stored_as_text(client, people):
    payload = "Robert'); DROP TABLE complaints;--"
    complaint = make_complaint(client, subject=payload)
    assert complaint.subject == payload
    assert client.get("/home?show=' OR 1=1--").status_code == 200
    assert client.get("/complaints/VB-' OR '1'='1").status_code == 404
    assert count(Complaint) == 1


def test_stored_xss_is_escaped(client, people):
    script = "<script>alert('xss')</script>"
    complaint = make_complaint(client, subject=script, body=script + " and <img src=x onerror=alert(1)>")
    client.post(f"/complaints/{complaint.reference}/reply", data={"body": script})
    assign(client, complaint, people["staff"])
    as_user(client, "staff@example.test")
    for path in (f"/complaints/{complaint.reference}", "/home"):
        body = client.get(path).data
        assert b"<script>alert" not in body
        assert b"<img src=x" not in body
        assert b"&lt;script&gt;" in body


# ---------- file uploads ----------

def upload(name, data):
    return {"evidence": (io.BytesIO(data), name)}


def stored_files(app) -> list[str]:
    folder = Path(app.config["UPLOAD_FOLDER"])
    return [f.name for f in folder.iterdir()] if folder.exists() else []


def test_valid_upload_is_stored_under_a_random_name_outside_static(app, client, people):
    complaint = make_complaint(client, **upload("my evidence.png", PNG))
    attachment = db.session.scalar(db.select(Attachment))
    assert attachment.complaint_id == complaint.id
    assert attachment.original_name == "my_evidence.png"
    assert attachment.stored_name != attachment.original_name and len(attachment.stored_name) == 36
    assert attachment.mime_type == "image/png"
    stored = Path(app.config["UPLOAD_FOLDER"]) / attachment.stored_name
    assert stored.read_bytes() == PNG
    assert Path(app.static_folder) not in stored.parents
    assert client.get(f"/static/{attachment.stored_name}").status_code == 404


@pytest.mark.parametrize("name,data,message", [
    ("malware.exe", b"MZ" + b"\x00" * 64, b"Only PDF, PNG and JPG"),
    ("shell.php", b"<?php system($_GET['c']); ?>", b"Only PDF, PNG and JPG"),
    ("page.html", b"<script>alert(1)</script>", b"Only PDF, PNG and JPG"),
    ("picture.svg", b"<svg onload=alert(1)>", b"Only PDF, PNG and JPG"),
    ("fake.png", b"<?php system($_GET['c']); ?>", b"do not match"),
    ("fake.pdf", PNG, b"do not match"),
    ("noextension", PNG, b"Only PDF, PNG and JPG"),
])
def test_dangerous_uploads_are_rejected(app, client, people, name, data, message):
    as_user(client, "alice@example.test")
    response = submit(client, **upload(name, data))
    assert response.status_code == 200
    assert message in response.data
    assert count(Complaint) == 0
    assert stored_files(app) == []
    assert db.session.scalar(db.select(AuditLog).filter_by(event="upload.rejected")) is not None


def test_oversized_upload_is_rejected(app, client, people):
    as_user(client, "alice@example.test")
    too_big = PDF + b"\x00" * app.config["MAX_UPLOAD_BYTES"]
    response = submit(client, **upload("big.pdf", too_big))
    assert response.status_code == 200 and b"larger than 5 MB" in response.data
    huge = PDF + b"\x00" * (app.config["MAX_CONTENT_LENGTH"] + 1)
    assert submit(client, **upload("huge.pdf", huge)).status_code == 413
    assert count(Complaint) == 0
    assert stored_files(app) == []


def test_path_traversal_and_double_extension_filenames(app, client, people):
    make_complaint(client, **upload("../../../app/static/evil.php.png", PNG))
    attachment = db.session.scalar(db.select(Attachment))
    assert "/" not in attachment.original_name and ".." not in attachment.original_name
    assert attachment.stored_name.endswith(".png") and "evil" not in attachment.stored_name
    assert stored_files(app) == [attachment.stored_name]
    assert not (Path(app.static_folder) / "evil.php.png").exists()


def test_download_is_authorised_and_forced_as_attachment(client, people):
    complaint = make_complaint(client, **upload("statement.pdf", PDF))
    attachment = db.session.scalar(db.select(Attachment))
    url = f"/attachments/{attachment.id}"

    response = client.get(url)
    assert response.status_code == 200 and response.data == PDF
    assert response.headers["Content-Disposition"].startswith("attachment")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in response.headers["Content-Security-Policy"]

    for email in ("bob@example.test", "staff@example.test"):
        as_user(client, email)
        assert client.get(url).status_code == 404
    assign(client, complaint, people["staff"])
    as_user(client, "staff@example.test")
    assert client.get(url).status_code == 200
    assert client.get("/attachments/9999").status_code == 404
