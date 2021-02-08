from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired,Email

class UserLoginForm(FlaskForm):
    # email, password, submit button
    email = StringField('email', validators = [DataRequired(),Email()])
    password = PasswordField('password', validators = [DataRequired()])
    #submit_button = SubmitField()

#corey schaeffer, real python, CT recommended book