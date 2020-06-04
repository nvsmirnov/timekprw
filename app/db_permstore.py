import os
import re
import shutil
import sqlite3
import tempfile

from app.whoami import whoami
from logging import debug, info, warning, error

try:
    from google.cloud import storage
except:
    # here, ignore this silently; you MUST make test when initializing gsc storage, or it will end up in 500 errors
    pass


# yeah I know it is way better to use object programming for my goals, but I'm too old for this stuff :-)

class ObjectWithWhoami(object):
    def whoami(self):
        #return f"{__self__.__class__.__name__}.{sys._getframe(1).f_code.co_name}"
        return f"{self.__class__.__name__}.{whoami(2)}"

class DBPermstoreAbstract(ObjectWithWhoami):

    app = None
    db = None
    db_file_path = None
    db_permstore_path = None
    storage_type = "abstract"

    def __init__(self, app, db, db_file_path, db_permstore_path):
        self.app = app
        self.db = db
        self.db_file_path = db_file_path
        self.db_permstore_path = db_permstore_path

    def __repr__(self):
        return f"{self.__class__.__name__}(working={self.db_file_path}, permanent={self.storage_type}:{self.db_permstore_path})"

    def get_from_permstore_actual(self, session):
        # redefine this in child classes
        error(f"internal error: {self.whoami()} called, you should not use this abstract class")

    def put_to_permstore_actual(self, session):
        # redefine this in child classes
        error(f"internal error: {self.whoami()} called, you should not use this abstract class")

    def get_from_permstore(self, session):
        # if database is not exists in working location, get it from permanent location
        debug(f"{self.whoami()} called")
        if not self.db_permstore_path:
            debug(f"{self.whoami()}: no permanent location defined, skipping")
            return True
        if os.path.exists(self.db_file_path):
            debug(f"{self.whoami()}: overriding {self.db_file_path} from permanent storage")
            #debug(f"{self.whoami()}: file {self.db_file_path} already exists, skipping")
            #return True
        db_file_dir = os.path.dirname(self.db_file_path)
        if not os.path.exists(db_file_dir):
            os.mkdir(db_file_dir)
        if self.get_from_permstore_actual(session):
            info(f"Made working database copy from permanent storage {self.storage_type}:{self.db_permstore_path}")
        else:
            info(f"Skipped or failed to make working database copy from permanent storage {self.storage_type}{self.db_permstore_path}")

        debug(f"{self.whoami()} finished")
        return True

    def put_to_permstore(self, session):
        # copy database from working to permanent location; better do this on every commit
        debug(f"{self.whoami()} called")
        self.put_to_permstore_actual(session)
        debug(f"{self.whoami()} finished")
        return True


class DBPermstoreFile(DBPermstoreAbstract):
    storage_type = "file"
    def get_from_permstore_actual(self, session):
        debug(f"{self.whoami()} called")
        #try:
        #    shutil.copyfile(self.db_permstore_path, self.db_file_path)
        #except FileNotFoundError as e:
        #    info(f"No permanent database file found at {self.db_permstore_path}, skipping file copy")
        #    pass
        perm = sqlite3.connect(self.db_permstore_path)
        working = sqlite3.connect(self.db_file_path)
        perm.backup(working)
        debug(f"{self.whoami()} finished")
        return True

    def put_to_permstore_actual(self, session):
        debug(f"{self.whoami()} called")
        working = sqlite3.connect(self.db_file_path)
        perm = sqlite3.connect(self.db_permstore_path)
        working.backup(perm)
        debug(f"{self.whoami()} finished")
        return True


class DBPermstoreGCS(DBPermstoreAbstract):
    storage_type = f"gcs({os.environ.get('GCS_BUCKET', 'bucket not defined')})"
    def get_from_permstore_actual(self, session):
        debug(f"{self.whoami()} called")
        try:
            storage_client = storage.Client()
            bucket = storage_client.bucket(os.environ.get("GCS_BUCKET", None))
            blob = bucket.blob(self.db_permstore_path)
            tmpf = tempfile.NamedTemporaryFile(prefix='timekprw-gcs-download')
            blob.download_to_filename(tmpf.name)
            perm = sqlite3.connect(tmpf.name)
            working = sqlite3.connect(self.db_file_path)
            perm.backup(working)
        except Exception as e:
            error(f"Failed to get database from permanent storage: {e}")
            debug(f"exception follows:", exc_info=True)
            return False
        debug(f"{self.whoami()} finished")
        return True

    def put_to_permstore_actual(self, session):
        debug(f"{self.whoami()} called")
        try:
            working = sqlite3.connect(self.db_file_path)
            tmpf = tempfile.NamedTemporaryFile(prefix='timekprw-gcs-upload')
            perm = sqlite3.connect(tmpf.name)
            working.backup(perm)
            storage_client = storage.Client()
            bucket = storage_client.bucket(os.environ.get("GCS_BUCKET", None))
            blob = bucket.blob(self.db_permstore_path)
            blob.upload_from_filename(tmpf.name)
        except Exception as e:
            error(f"Failed to save database to permanent storage: {e}")
            debug(f"exception follows:", exc_info=True)
        debug(f"{self.whoami()} finished")
        return True


def get_permstore_instance(app, db):
    db_permstore_instance = None
    if not app.config['DATABASE_PERMSTORE_URL']:
        debug(f"{whoami()}: no DATABASE_PERMSTORE_URL is set, skipping")
        return db_permstore_instance
    else:
        m = re.match('^([^\:]+)\:(.+)$', app.config['DATABASE_PERMSTORE_URL'], re.I)
        if not m:
            error(f"{whoami()}: failed to parse DATABASE_PERMSTORE_URL='{app.config['DATABASE_PERMSTORE_URL']}', use 'scheme:path' format")
        else:
            url_type = m.group(1).lower()
            path = m.group(2)
            if url_type == 'file':
                db_permstore_instance = DBPermstoreFile(app, db, app.config['DATABASE_FILE_PATH'], path)
            elif url_type == 'gcs':
                if not os.environ.get('GCS_BUCKET', None):
                    error(f"Refusing to use GCS as permanent store because GCS_BUCKET is not set")
                else:
                    try:
                        from google.cloud import storage
                    except Exception as e:
                        error(f"Internal error in {whoami()}: failed to initialize GCS API: {e}")
                    else:
                        db_permstore_instance = DBPermstoreGCS(app, db, app.config['DATABASE_FILE_PATH'], path)
            else:
                error(f"{whoami()}: unknown permanent storage type '{url_type}', failed to initialize permanent storage")
    debug(f"{whoami()}: db permanent storage is {db_permstore_instance}")
    return db_permstore_instance

