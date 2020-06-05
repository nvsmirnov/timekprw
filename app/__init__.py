import os

from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from app.db_permstore import *

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config.from_object(Config)

db = SQLAlchemyWithPermStorage(app)
migrate = Migrate(app, db)

#db_permstore_instance = get_permstore_instance(app, db)
#
#if db_permstore_instance:
#    from sqlalchemy import event
#    @event.listens_for(db.session, 'after_commit')
#    def receive_after_commit(session):
#        db_permstore_instance.put_to_permstore(session)


# how to migrate db (based on https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-iv-database):
# set environment variables:
#   FLASK_APP=main.py
#   DATABASE_URL
# ("flask db" is command is added by Flask-Migrate)

# Overall process:
#   1. Create the migration repository. Run it once when created first model, (or before?)
#      flask db init
#   2. Create migration scripts. Every time when model changes:
#      flask db migrate -m "Message"
#   3. Upgrade database (this app should do upgrades in-place):
#      flask db upgrade

# to look from DB's perspective what version it is now: select * from alembic_version
