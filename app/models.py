#
# WARNING! Don't forget to do fask db migrate after changing models!
#

from app import db
from app.exceptions import *

import datetime
import random

from flask_login import UserMixin
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property

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
    email = db.Column(db.String(256), index=True, unique=True)

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
    _pin = db.Column('pin', db.String(6))
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
        if pin != self.pin:
            # TODO: check pin age and reset it if it is too old
            return False
        else:
            return True

    def checkauth(self, authkey):
        raise TimekprwException('Authentication not implemented yet')


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
