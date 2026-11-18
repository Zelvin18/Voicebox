"""Authentication, session and access-control tests."""
from app import create_app
from app.extensions import db
from app.models import AuditLog, Role, User
from tests.conftest import PASSWORD, login

import pytest

REGISTRATION = {
    "full_name": "Tariro Moyo",
    "student_id": "cu-2024-01234",
    "email": "T.Moyo@Example.com",
    "password": PASSWORD,
    "confirm": PASSWORD,
}


def events(event):
    return db.session.scalars(db.select(AuditLog).filter_by(event=event)).all()


# ---------- registration ----------

def test_register_creates_student_with_hashed_password(client):
    response = client.post("/register", data=REGISTRATION)
    assert response.status_code == 302
    user = db.session.scalar(db.select(User))
    assert user.email == "t.moyo@example.com"
    assert user.student_id == "CU-2024-01234"
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash


def test_register_ignores_role_field(client):
    client.post("/register", data={**REGISTRATION, "role": "admin"})
    assert db.session.scalar(db.select(User)).role == Role.STUDENT


@pytest.mark.parametrize("password", ["short", "password1234", "tariro-is-my-name", "aaaaaaaaaaaaaa"])
def test_register_rejects_weak_passwords(client, password):
    response = client.post("/register", data={**REGISTRATION, "password": password, "confirm": password})
    assert response.status_code == 200
    assert db.session.scalar(db.select(User)) is None


def test_register_duplicate_does_not_reveal_which_field(client, make_user):
    make_user(email="t.moyo@example.com")
    response = client.post("/register", data=REGISTRATION)
    assert b"could not create an account" in response.data
    assert db.session.scalar(db.select(db.func.count(User.id))) == 1


# ---------- sign-in ----------

def test_login_with_email_or_student_id(client, make_user):
    make_user()
    assert login(client).headers["Location"] == "/home"
    client.post("/logout")
    assert login(client, identifier="cu-2024-00001").headers["Location"] == "/home"


def test_login_failure_message_is_generic(client, make_user):
    make_user()
    wrong_password = login(client, password="not the password!")
    unknown_user = login(client, identifier="nobody@example.test")
    assert wrong_password.status_code == unknown_user.status_code == 200
    assert b"Incorrect details" in wrong_password.data
    assert b"Incorrect details" in unknown_user.data


def test_account_locks_after_five_failures(client, make_user):
    make_user()
    for _ in range(5):
        login(client, password="not the password!")
    assert db.session.scalar(db.select(User)).is_locked
    # Even the right password is refused while locked.
    assert login(client).status_code == 200
    assert client.get("/home").status_code == 302
    assert any(e.outcome == "locked" for e in events("auth.login"))


def test_open_redirect_is_blocked(client, make_user):
    make_user()
    response = client.post("/login?next=https://evil.example/", data={"identifier": "student@example.test",
                                                                      "password": PASSWORD})
    assert response.headers["Location"] == "/home"
    client.post("/logout")
    response = client.post("/login?next=/account/security", data={"identifier": "student@example.test",
                                                                  "password": PASSWORD})
    assert response.headers["Location"] == "/account/security"


def test_password_never_written_to_audit_log(client, make_user):
    make_user()
    login(client, password="not the password!")
    login(client)
    for entry in db.session.scalars(db.select(AuditLog)):
        assert PASSWORD not in f"{entry.actor}{entry.target}{entry.detail}"
        assert "not the password!" not in f"{entry.actor}{entry.target}{entry.detail}"


# ---------- sessions ----------

def test_pages_require_login(client):
    for path in ("/home", "/account/security", "/admin/users"):
        response = client.get(path)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


def test_session_cookie_flags(client, make_user):
    make_user()
    cookie = login(client).headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_logout_needs_post_and_kills_the_session(client, make_user):
    make_user()
    login(client)
    assert client.get("/logout").status_code == 405
    stolen_cookie = client.get_cookie("vb_session").value
    client.post("/logout")
    assert client.get("/home").status_code == 302
    # Replaying the old cookie must not work: the session was revoked server-side.
    client.set_cookie("vb_session", stolen_cookie)
    assert client.get("/home").status_code == 302


def test_change_password_signs_out_other_sessions(app, make_user):
    make_user()
    laptop, phone = app.test_client(), app.test_client()
    login(laptop)
    login(phone)
    new = "a brand new passphrase"
    response = laptop.post("/account/security", data={"current_password": PASSWORD, "password": new, "confirm": new})
    assert response.status_code == 302
    assert laptop.get("/home").status_code == 200
    assert phone.get("/home").status_code == 302
    assert login(phone, password=new).headers["Location"] == "/home"


def test_absolute_session_timeout(client, make_user):
    make_user()
    login(client)
    with client.session_transaction() as session:
        session["login_at"] = 0
    assert client.get("/home").status_code == 302


# ---------- access control ----------

def test_student_and_staff_cannot_open_admin_pages(client, make_user):
    make_user()
    make_user(email="staff@example.test", role=Role.STAFF, name="Staff Member")
    for identifier in ("student@example.test", "staff@example.test"):
        login(client, identifier=identifier)
        assert client.get("/admin/users").status_code == 403
        client.post("/logout")
    assert len(events("access.denied")) == 2


def test_admin_can_open_admin_pages(client, make_user):
    make_user(email="admin@example.test", role=Role.ADMIN, name="Admin Person")
    login(client, identifier="admin@example.test")
    response = client.get("/admin/users")
    assert response.status_code == 200
    assert b"admin@example.test" in response.data


# ---------- hardening ----------

def test_security_headers(client):
    headers = client.get("/login").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"


def test_csrf_token_is_required(make_user):
    app = create_app("testing")
    app.config["WTF_CSRF_ENABLED"] = True
    with app.app_context():
        db.create_all()
        response = app.test_client().post("/logout")
        assert response.status_code == 400
        db.drop_all()


def test_user_input_is_escaped(client, make_user):
    make_user(name="<script>alert(1)</script>")
    login(client)
    body = client.get("/home").data
    assert b"<script>alert(1)</script>" not in body
    assert b"&lt;script&gt;" in body


def test_audit_log_is_append_only(client, make_user):
    make_user()
    login(client)
    entry = db.session.scalar(db.select(AuditLog))
    entry.outcome = "tampered"
    with pytest.raises(RuntimeError):
        db.session.commit()
    db.session.rollback()
    db.session.delete(db.session.scalar(db.select(AuditLog)))
    with pytest.raises(RuntimeError):
        db.session.commit()
    db.session.rollback()


def test_production_requires_secret_key(monkeypatch):
    import config
    monkeypatch.setattr(config.ProductionConfig, "SECRET_KEY", None)
    with pytest.raises(RuntimeError):
        create_app("production")
