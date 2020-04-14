import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite://' # empty url for in-memory
        #'sqlite:///' + os.path.join(basedir, 'data/timekprw.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
