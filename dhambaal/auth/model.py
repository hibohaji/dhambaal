from dhambaal import db, login_manager
from flask_login import UserMixin
from datetime import datetime

# Load User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get_or_404(user_id)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(244), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(244), nullable=False)
    confirmed_at = db.Column(db.DateTime())


    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()
    
    @classmethod
    def validate_email(cls, email):
        email = User.query.filter_by(email=email).first()
        if email:
            return True
    @classmethod
    def validate_username(cls, username):
        username = User.query.filter_by(username=username).first()
        if username:
            return True



