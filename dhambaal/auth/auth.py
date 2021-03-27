from flask import Blueprint, render_template, url_for, redirect, flash
from dhambaal.auth.model import User
from dhambaal.auth.forms import LoginForm, RegisterForm
#from werkzeug.security import check_password_hash, generate_password_hash
from flask_bcrypt import check_password_hash, generate_password_hash



auth = Blueprint('auth', __name__, template_folder="templates")

@auth.route('/dashboard/user/register', methods=['POST','GET'])
def register_user():
    form=RegisterForm()
    if form.validate_on_submit():
        #if user already login we need to redirect to dashboard
        # TODO1 : check if admin or staff
        # TODO2 : hassh user password
        use= User(name=form.name.data, email= form.email.data, username=form.username.data,
                    password= generate_password_hash(form.password.data).decode('utf-8'))

        if User.validate_email(form.email.data):
            flash('Email already taken, please choose diffrent one', 'is-warning')
            return redirect(url_for('auth.register_user'))

        if User.validate_username(form.username.data):
            flash('Username already taken, please choose diffrent one', 'is-warning')
            return redirect(url_for('auth.register_user'))
        user.save_db()
        flash("user created successfully", 'is-success')
        return redirect(url_for("auth.users"))
    return render_template('register.html', form=form)
        

@auth.route("/dashboard/users")
def users():
    users = User.query.all()
    return render_template("users.html", users=users)


@auth.route("/login", methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        # TODO1 : Compare hashed password with users password
        # TODO2. Check if email and password match
        #  User login
        flash("Logged in successfully", 'is-success')
        return redirect(url_for("dashboard.index"))
    return render_template("login.html", form=form)