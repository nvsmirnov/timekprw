import os

from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_script import Manager

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# how to migrate db (based on https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database):
# set environment variables:
#   FLASK_APP=main.py
#   DATABASE_URL
# ("flask db" is command is added by Flask-Migrate)
# 1. Create the migration repository. Run it once when created first model, (or before?)
# flask db init
# 2. Create migration scripts. Every time when model changes:
# flask db migrate -m "Message"
# 3. Upgrade database:
# flask db upgrade