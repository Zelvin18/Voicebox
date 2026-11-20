import pytest
from flask import g

from app import create_app
from app.extensions import db
from app.models import Role, User
from app.security import hash_password

PASSWORD = "correct horse battery"


@pytest.fixture
def app(tmp_path):
    app = create_app("testing")
    app.config["UPLOAD_FOLDER"] = str(tmp_path / "uploads")

    # The fixture keeps one app context open, so Flask-Login's per-request user
    # cache would leak between requests. Clear it so each request loads the user
    # from its own cookie, exactly as in production.
    def forget_cached_user():
        g.pop("_login_user", None)
    app.before_request_funcs.setdefault(None, []).insert(0, forget_cached_user)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    def _make(email="student@example.test", role=Role.STUDENT, student_id="CU-2024-00001", name="Test Student"):
        user = User(email=email, full_name=name, role=role, password_hash=hash_password(PASSWORD),
                    student_id=student_id if role == Role.STUDENT else None)
        db.session.add(user)
        db.session.commit()
        return user
    return _make


def login(client, identifier="student@example.test", password=PASSWORD, **kwargs):
    return client.post("/login", data={"identifier": identifier, "password": password}, **kwargs)
