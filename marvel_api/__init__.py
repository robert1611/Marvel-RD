from flask import Flask
from marvel_api.config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Import for Flask Login
from flask_login import LoginManager

# Import For AuthLib integrations
from authlib.integrations.flask_client import OAuth

# import for Flask-Marshmallow
from flask_marshmallow import Marshmallow

from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(Config)

CORS(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'signin'

oauth = OAuth(app)
ma = Marshmallow(app)

from marvel_api import routes, models