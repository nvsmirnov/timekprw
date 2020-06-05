import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime

from app.whoami import whoami
from logging import debug, info, warning, error

from flask_sqlalchemy import SQLAlchemy

try:
    from google.cloud import storage
except:
    # here, ignore this silently; you MUST make test when initializing gsc storage, or it will end up in 500 errors
    pass


# yeah I know it is way better to use object programming for my goals, but I'm too old for this stuff :-)

class ObjectWithWhoami(object):
    def whoami(self):
        return f"{self.__class__.__name__}.{whoami(2)}"


# Priorities for synchronization to persistent storage, if configured
SyncPriorityUrgent = 1   # Sync right now anyway
SyncPriorityNormal = 2   # Sync now if throttling is not in place, or delay sync
SyncPriorityDelayed = 3  # Delayed sync

# Sync limits for Normal priority
SyncLimitsNormal = {
    "day": 100,
    "hour": 20
}
SyncPeriodMasks = {
    "day": "%Y%m%d",
    "hour": "%Y%m%d%H"
}

class SQLAlchemyWithPermStorage(SQLAlchemy):

    db_permstore_instance = None
    have_commits_to_sync = False

    def __init__(self, app):
        super().__init__(app=app)
        self.db_permstore_instance = self.get_permstore_instance(app)

    def whoami(self):
        # could not inherit from ObjectWithWhoami bacause of problem with passing args to super init in that case
        return f"{self.__class__.__name__}.{whoami(2)}"

    def schedule_sync(self, sync_priority):
        """Call this to sync to permanent store, with checking for thresholds and commits that are not synced"""
        if self.db_permstore_instance:
            if not self.have_commits_to_sync:
                return False
            self.db_permstore_instance.schedule_sync(sync_priority)

    def commit_and_sync(self, sync_priority=SyncPriorityNormal):
        """Issue commit to DB and, if persistent storage is enabled, do a sync or schedule it for later"""
        # can't use after_commit hook because we need to pass sync_priority when committing
        self.session.commit()
        self.have_commits_to_sync = True
        self.schedule_sync(sync_priority)

    def get_permstore_instance(self, app):
        db_permstore_instance = None
        if not app.config['DATABASE_PERMSTORE_URL']:
            debug(f"{self.whoami()}: no DATABASE_PERMSTORE_URL is set, skipping")
            return db_permstore_instance
        else:
            m = re.match('^([^\:]+)\:(.+)$', app.config['DATABASE_PERMSTORE_URL'], re.I)
            if not m:
                error(f"{self.whoami()}: failed to parse DATABASE_PERMSTORE_URL='{app.config['DATABASE_PERMSTORE_URL']}', use 'scheme:path' format")
            else:
                url_type = m.group(1).lower()
                path = m.group(2)
                if url_type == 'file':
                    db_permstore_instance = DBPermstoreFile(app, self, app.config['DATABASE_FILE_PATH'], path)
                elif url_type == 'gcs':
                    if not os.environ.get('GCS_BUCKET', None):
                        error(f"Refusing to use GCS as permanent store because GCS_BUCKET is not set")
                    else:
                        try:
                            from google.cloud import storage
                        except Exception as e:
                            error(f"Internal error in {self.whoami()}: failed to initialize GCS API: {e}")
                        else:
                            db_permstore_instance = DBPermstoreGCS(app, self, app.config['DATABASE_FILE_PATH'], path)
                else:
                    error(f"{self.whoami()}: unknown permanent storage type '{url_type}', failed to initialize permanent storage")
        debug(f"{self.whoami()}: db permanent storage is {db_permstore_instance}")
        return db_permstore_instance


class DBPermstoreAbstract(ObjectWithWhoami):

    app = None
    db = None
    db_file_path = None
    db_permstore_path = None
    storage_type = "abstract"

    # it is better to have these in DB, so they could survive restarts
    # but on other side - it is good to have way to reset limits (so restart do that, simpler is better...)
    syncs_per_period = {
        # increment "count" when you are in this period, replace period and reset count when period differs from current
        "day":  {"period": "YYYYMMDD",   "count": 0},
        "hour": {"period": "YYYYMMDDhh", "count": 0},
    }

    def __init__(self, app, db, db_file_path, db_permstore_path):
        self.app = app
        self.db = db
        self.db_file_path = db_file_path
        self.db_permstore_path = db_permstore_path

    def __repr__(self):
        return f"{self.__class__.__name__}(working={self.db_file_path}, permanent={self.storage_type}:{self.db_permstore_path})"

    def update_syncs_periods(self):
        """Checks if saved periods are matching current time, if not, reset counters and update period names.
        Call this before any checking or updating counters."""
        now = datetime.now()
        for period in ["day", "hour"]:
            current_period_mask = now.strftime(SyncPeriodMasks[period])
            if self.syncs_per_period[period]["period"] != current_period_mask:
                self.syncs_per_period[period]["period"] = current_period_mask
                self.syncs_per_period[period]["count"] = 0

    def need_throttle(self, period):
        """Checks if counter for specified period type ('day'/'hour') is exceeding throttling threshold.
        Prior to use this, call self.update_syncs_periods().
        Returns True/False."""
        if self.syncs_per_period[period]["count"] >= SyncLimitsNormal[period]:
            return True
        else:
            return False

    def schedule_sync(self, sync_priority):
        """Schedule sync to permstore."""
        do_sync = False
        self.update_syncs_periods()
        if sync_priority == SyncPriorityUrgent:
            debug(f"{self.whoami()}: urgent sync called")
            do_sync = True
        elif sync_priority == SyncPriorityNormal:
            debug(f"{self.whoami()}: normal sync called")
            do_sync = True
            for period in ["hour", "day"]:
                if self.need_throttle(period):
                    debug(f"{self.whoami()}: '{period}' limit reached, throttling sync, permstore usage counters: {self.syncs_per_period}")
                    do_sync = False
                    break
        elif sync_priority == SyncPriorityDelayed:
            debug(f"{self.whoami()}: delayed sync called")
            if self.syncs_per_period["day"]["count"] <= 0:
                debug(f"{self.whoami()}: there were no syncs today, syncing now")
                do_sync = True
            else:
                debug(f"{self.whoami()}: skipping sync now, permstore usage counters: {self.syncs_per_period}")
        else:
            error(f"{self.whoami()}: unknown sync priority ({sync_priority}), skipping sync this time")
        if do_sync:
            self.put_to_permstore()
            self.db.have_commits_to_sync = False
            self.syncs_per_period["day"]["count"] += 1
            self.syncs_per_period["hour"]["count"] += 1
            debug(f"{self.whoami()}: permstore usage counters: {self.syncs_per_period}")

    def get_from_permstore_actual(self):
        # redefine this in child classes
        error(f"internal error: {self.whoami()} called, you should not use this abstract class")

    def put_to_permstore_actual(self):
        # redefine this in child classes
        error(f"internal error: {self.whoami()} called, you should not use this abstract class")

    def get_from_permstore(self):
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
        if self.get_from_permstore_actual():
            info(f"Made working database copy from permanent storage {self.storage_type}:{self.db_permstore_path}")
        else:
            info(f"Skipped or failed to make working database copy from permanent storage {self.storage_type}{self.db_permstore_path}")

        debug(f"{self.whoami()} finished")
        return True

    def put_to_permstore(self):
        # copy database from working to permanent location; better do this on every commit
        debug(f"{self.whoami()} called")
        self.put_to_permstore_actual()
        debug(f"{self.whoami()} finished")
        return True


class DBPermstoreFile(DBPermstoreAbstract):
    storage_type = "file"
    def get_from_permstore_actual(self):
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

    def put_to_permstore_actual(self):
        debug(f"{self.whoami()} called")
        working = sqlite3.connect(self.db_file_path)
        perm = sqlite3.connect(self.db_permstore_path)
        working.backup(perm)
        debug(f"{self.whoami()} finished")
        return True


class DBPermstoreGCS(DBPermstoreAbstract):
    storage_type = f"gcs({os.environ.get('GCS_BUCKET', 'bucket not defined')})"
    def get_from_permstore_actual(self):
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

    def put_to_permstore_actual(self):
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


