from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, SelectField, RadioField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
# from dhambaal.dashboard.models.Categories import Category
from dhambaal.auth.model import User


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=3)])
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=15)])
    email = StringField('Email', validators=[
                        DataRequired(), Email()])
    # TODO 1. Create strong password validation in production
    password = PasswordField("Password", validators=[
        DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(), EqualTo('password', message="Confirm Password field must be equal to password")])
    submit = SubmitField('Create')

    def validate_username(self, username):
        username = User.query.filter_by(username=self.username.data).first()
        if username:
            raise ValidationError("Username is taken, try diffrent one")

    def validate_email(self, email):
        email = User.query.filter_by(email=self.email.data).first()
        if email:
            raise ValidationError("Email is taken, try diffrent one")


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        DataRequired(), Email()], render_kw={"placeholder": "Your Email"})
    password = PasswordField("Password", validators=[
        DataRequired()], render_kw={"placeholder": "Your Password"})
    submit = SubmitField('Login')