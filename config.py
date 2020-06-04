import os
import re
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # you may either use sqlite database (read below), or other database
    # in case of sqlite, the program is designed to be compatible with cloud platforms:
    # it maintains permanent copy of database in some place (i.e., object storage)
    # and makes working copy from permanent place, and updates permanent storage on commits
    # this is done so we can use cloud platforms for free (i.e. GCP+GCS or AWS+S3 are free but MySQL is paid)
    #
    # set env DATABASE_PERMSTORE_URL to where is the permanent storage of sqlite database is
    #   formats are:
    #     file:name_of_file
    #     gcs:path_in_default_bucket
    #       in this case, you must define env GCS_BUCKET and set bucket name there
    # OR
    # set env DATABASE_URL such as "mysql+pymysql://...
    #
    DATABASE_PERMSTORE_URL = os.environ.get('DATABASE_PERMSTORE_URL', None)
    if DATABASE_PERMSTORE_URL:
        # store DB permanently in DATABASE_PERMSTORE_URL, and working copy in DATABASE_PATH
        DATABASE_PATH = os.path.join(basedir, "data/timekprw.sqlite.db")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + DATABASE_PATH
    else:
        # use specified DB URL
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
            'sqlite://'  # empty url for in-memory
            #'sqlite:///' + os.path.join(basedir, 'data/timekprw.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
