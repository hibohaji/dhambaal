from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from dhambaal.config import DevelopmentConfig

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'thisisverysuecure'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dhambaal.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# TODO1 : The application should automatically load configurations
app.config.from_object(DevelopmentConfig)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)

print(app.config)
# Create Tables before running application


@app.before_first_request
def create_tables():
    db.create_all()


# REGISTER BLUEPRINTS
from dhambaal.dashboard.views import dashboard
from dhambaal.views import site
from dhambaal.auth.auth import auth
app.register_blueprint(dashboard)
app.register_blueprint(site)
app.register_blueprint(auth)