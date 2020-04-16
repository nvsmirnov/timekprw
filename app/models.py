from app import db
from flask_login import UserMixin
from sqlalchemy.orm import relationship

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
