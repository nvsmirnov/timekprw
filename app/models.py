#
# WARNING! Don't forget to do fask db migrate after changing models!
#

from app import db
from app.exceptions import *
from app.db_permstore import SyncPriorityDelayed, SyncPriorityNormal, SyncPriorityUrgent

import datetime
import random
import string
from passlib.hash import pbkdf2_sha512

from flask_login import UserMixin
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property

from logging import debug, info, warning, error

association_Manager_ManagedHost = db.Table(
    'association_manager_managedhost', db.metadata,
    db.Column('manager_id',     db.Integer, db.ForeignKey('manager.id')),
    db.Column('managedhost_id', db.Integer, db.ForeignKey('managedhost.id')),
)

ExtAuthTypeGoogleAuth = "googleauth"
class Manager(db.Model, UserMixin):  # UserMixin for flask_login
    """
    User that manages time of managed users
    """
    __tablename__ = 'manager'
    id = db.Column(db.Integer, primary_key=True)
    ext_auth_type = db.Column(db.String(256), index=True)  # type of external authentication system, one of ManagerExtTypeXXXXX
    ext_auth_id = db.Column(db.String(256), index=True)  # id in external authentication system
    name = db.Column(db.Text)
    email = db.Column(db.String(256), index=True)

    hosts = relationship(
        "ManagedHost",
        secondary=association_Manager_ManagedHost,
        back_populates="managers"
    )

    def __repr__(self):
        return f"<Manager id:{self.id}, ext_id:{self.ext_auth_type}/{self.ext_auth_id}, email:{self.email}>"
    def __str__(self):
        return f"{self.ext_auth_type}/{self.email}"

class ManagedHost(db.Model):
    """
    Managed host
    """
    __tablename__ = 'managedhost'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True)
    hostname = db.Column(db.String(256), index=True)

    # time when there was last correctly authenticated request from this host
    lastauthaccess = db.Column(db.DateTime)

    # pin is used when host added to generate authentication key
    _pin = db.Column('pin', db.String(6), index=True)
    pin_whenset = db.Column(db.DateTime)

    authkey = db.Column(db.String(256))
    authkey_trycount = db.Column(db.Integer)

    auth_lastsuccess = db.Column(db.DateTime)

    users = relationship("ManagedUser", back_populates="host")
    managers = relationship(
        "Manager",
        secondary=association_Manager_ManagedHost,
        back_populates="hosts"
    )

    def __repr__(self):
        return f"<ManagedHost id:{self.id}, uuid:{self.uuid}, hostname:{self.hostname}>"
    def __str__(self):
        return f"{self.hostname}"

    @hybrid_property
    def pin(self):
        return self._pin

    @pin.setter
    def pin(self, value):
        self._pin = value
        self.pin_whenset = datetime.datetime.utcnow()

    def pin_generate(self):
        # check if we have too many hosts with pin set and remove some of them to avoid collisions
        hosts_pending = ManagedHost.query. \
            filter(ManagedHost.pin != None). \
            order_by(ManagedHost.pin_whenset).all()  # TODO: that should be dangerous
        while len(hosts_pending) > 1: # TODO: change to 999 when tested
            popped = hosts_pending.pop(0)
            popped.pin = None;
        while True:
            pin = ''.join(random.choice('0123456789') for x in range(6))
            if not ManagedHost.query.filter_by(pin=pin).first():
                # ok, there is no such pin yet
                break
        self.pin = pin

    def checkpin(self, pin):
        # there was a thought to add some more logic to that, but evetually it reduced to this :)
        if pin != self.pin:
            return False
        else:
            return True

    def authkey_check(self, authkey):
        """
        Check authkey, return True or False
        may raise TimekprwException
        Performs DB commit
        """
        try:
            if not self.authkey:
                return False
            rv = pbkdf2_sha512.verify(authkey, self.authkey)
            if not rv:
                if self.authkey_trycount is None:
                    self.authkey_trycount = 0
                self.authkey_trycount += 1
            else:
                self.auth_lastsuccess = datetime.datetime.utcnow()
            db.commit_and_sync(sync_priority=SyncPriorityDelayed)
            return rv
        except Exception as e:
            debug(f'got exception in authkey_check: {e}, trace follows:', exc_info=True)
            raise TimekprwException('Failed to check authkey')

    def authkey_generate(self):
        """
        Generaty authkey, return list: [authkey_plain, authkey_hash]
        authkey_salt and authkey_hash are to be stored in DB, authkey_plain is to be returned to the REST client
        """
        authkey_plain = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(64))
        authkey_hash = pbkdf2_sha512.hash(authkey_plain)
        return [authkey_plain, authkey_hash]


class ManagedUser(db.Model):
    """
    Managed user
    """
    __tablename__ = 'manageduser'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), index=True)
    login = db.Column(db.String(256), index=True)

    host_id = db.Column(db.Integer, db.ForeignKey('managedhost.id'))
    host = relationship("ManagedHost", back_populates="users")

    timeoverrides = relationship("TimeOverride", back_populates="user")

    def __repr__(self):
        return f"<ManagedUser id:{self.id}, uuid:{self.uuid}, login:{self.login}@{repr(self.host)}>"
    def __str__(self):
        return f"{self.login}@{self.host.hostname}"

TimeOverrideStatusQueued  = 1
TimeOverrideStatusApplied = 2
class TimeOverride(db.Model):
    """
    TimeKpr override time limit for current day
    """
    __tablename__ = 'timeoverride'
    id = db.Column(db.Integer, primary_key=True)

    amount = db.Column(db.Integer)  # amount of time to add to or subtract from current time limit
    status = db.Column(db.Integer, index=True)  # status of this override - i.e. is it applied or queued for apply

    user_id = db.Column(db.Integer, db.ForeignKey('manageduser.id'))
    user = relationship("ManagedUser", back_populates="timeoverrides")
    owner_id = db.Column(db.Integer, db.ForeignKey('manager.id'))
    owner = relationship("Manager")

    def __repr__(self):
        return f"<TimeOverride id:{self.id}, " \
               f"user={self.user.login}@{self.user.host.hostname}, " \
               f"amount:{self.amount}, status:{self.status}>"
