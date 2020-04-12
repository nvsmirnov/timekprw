import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    #SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
    #    'sqlite:///' + os.path.join(basedir, 'data/dev.sqlite')
    SQLALCHEMY_DATABASE_URI = 'sqlite://' # empty url for in-memory
    SQLALCHEMY_TRACK_MODIFICATIONS = False
