from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, BooleanField, SubmitField, IntegerField, Label
from wtforms.validators import DataRequired

class TimeForm(FlaskForm):
    # TODO: is this hiddenfield needed? There is uuid in URL already
    useruuid = HiddenField('useruuid')
    username = Label('username', 'User: ')
    amount = IntegerField('Time amount', validators=[DataRequired()])
    submit = SubmitField('Go!')

class HostAddForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired()])
    submit = SubmitField('Go!')

class HostRemoveForm(FlaskForm):
    submit = SubmitField('Yes, delete this host')

class HostAddManagerForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Go!')

class HostAddUserForm(FlaskForm):
    login = StringField('Login', validators=[DataRequired()])
    submit = SubmitField('Go!')