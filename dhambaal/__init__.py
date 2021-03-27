from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_migrate import Migrate
from flask_login import LoginManager
#from flask-bcrypt import 
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = "thisisverysecure"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dhambaal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

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