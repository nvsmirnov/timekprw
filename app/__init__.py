import os

from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
#from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config.from_object(Config)
db = SQLAlchemy(app)
#migrate = Migrate(app, db)
