"""Auth forms. Every rule here is enforced on the server."""
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError

from ..security import MAX_PASSWORD_LENGTH, password_problem


class LoginForm(FlaskForm):
    identifier = StringField("Email or student ID", validators=[DataRequired(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=MAX_PASSWORD_LENGTH)])


class RegisterForm(FlaskForm):
    full_name = StringField("Full name", validators=[
        DataRequired(), Length(min=3, max=120),
        Regexp(r"^[A-Za-z][A-Za-z .'\-]+$", message="Use letters, spaces, hyphens and apostrophes only."),
    ])
    student_id = StringField("Student ID", validators=[
        DataRequired(),
        Regexp(r"^[Cc][Uu]-\d{4}-\d{5}$", message="Use the format CU-2024-01234."),
    ])
    email = StringField("University email", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm = PasswordField("Confirm password", validators=[
        DataRequired(), EqualTo("password", message="The passwords do not match."),
    ])

    def validate_email(self, field):
        allowed = current_app.config["ALLOWED_EMAIL_DOMAINS"]
        if allowed and field.data.rsplit("@", 1)[-1].lower() not in allowed:
            raise ValidationError("Use your university e-mail address.")

    def validate_password(self, field):
        problem = password_problem(field.data, self.email.data, self.student_id.data,
                                   *(self.full_name.data or "").split())
        if problem:
            raise ValidationError(problem)


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[
        DataRequired(), Length(max=MAX_PASSWORD_LENGTH),
    ])
    password = PasswordField("New password", validators=[DataRequired()])
    confirm = PasswordField("Confirm new password", validators=[
        DataRequired(), EqualTo("password", message="The passwords do not match."),
    ])

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user = user

    def validate_password(self, field):
        problem = password_problem(field.data, self._user.email, self._user.student_id or "",
                                   *self._user.full_name.split())
        if problem:
            raise ValidationError(problem)
        if field.data == self.current_password.data:
            raise ValidationError("Choose a password you have not just used.")
