from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import BooleanField, RadioField, SelectField, StringField, TextAreaField
from wtforms.validators import AnyOf, DataRequired, InputRequired, Length

from ..models import CATEGORIES, Status


def _strip(value):
    return value.strip() if isinstance(value, str) else value


class ComplaintForm(FlaskForm):
    category = RadioField("Category", choices=[(c, c) for c in CATEGORIES],
                          validators=[InputRequired(message="Choose a category.")])
    subject = StringField("Subject", filters=[_strip], validators=[
        DataRequired(message="Give your complaint a short subject."), Length(min=5, max=120),
    ])
    body = TextAreaField("What happened?", filters=[_strip], validators=[
        DataRequired(message="Describe what happened."), Length(min=20, max=4000),
    ])
    evidence = FileField("Evidence")


class ReplyForm(FlaskForm):
    body = TextAreaField("Reply", filters=[_strip], validators=[
        DataRequired(message="Write a message first."), Length(max=2000),
    ])
    internal = BooleanField("Internal note (not shown to the student)")


class StatusForm(FlaskForm):
    status = StringField(validators=[
        AnyOf([Status.IN_PROGRESS, Status.AWAITING_STUDENT, Status.RESOLVED]),
    ])


class AssignForm(FlaskForm):
    staff_id = SelectField("Assign to", coerce=int, validators=[InputRequired()])
