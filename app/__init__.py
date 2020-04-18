import os

from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config.from_object(Config)
db = SQLAlchemy(app)

migrate = Migrate(app, db)

# don't sure if we should do this here and run every time we start app
# based on https://stackoverflow.com/questions/36698070/how-to-use-flask-migrate-with-google-app-engine
migratemanager = Manager(app)
migratemanager.add_command('db', MigrateCommand)

# how to migrate db (from https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database):
# ("flask db" is command is added by Flask-Migrate)
# 1. Create the migration repository. Run it once when created first model, (or before?)
# flask db init
# 2. Create migration scripts. Every time when model changes:
# flask db migrate -m "Message"
# 3. Upgrade database:
# flask db upgrade