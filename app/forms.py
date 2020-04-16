from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, BooleanField, SubmitField, IntegerField, Label
from wtforms.validators import DataRequired

class TimeForm(FlaskForm):
    useruuid = HiddenField('useruuid')
    username = Label('username', 'User: ')
    amount = IntegerField('Time amount', validators=[DataRequired()])
    submit = SubmitField('Go!')