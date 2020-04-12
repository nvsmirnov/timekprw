from flaskapp import db
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
    ext_auth_type = db.Column(db.Text, index=True)  # type of external authentication system, one of ManagerExtTypeXXXXX
    ext_auth_id = db.Column(db.Text, index=True)  # id in external authentication system
    name = db.Column(db.Text, index=True)
    email = db.Column(db.Text, index=True, unique=True)
    picture = db.Column(db.Text)

    hosts = relationship(
        "ManagedHost",
        secondary=association_Manager_ManagedHost,
        back_populates="managers"
    )

    def __repr__(self):
        return f"<Manager id:{self.id}, ext_id: {self.ext_auth_id}, name={self.name}, email={self.email}>"

class ManagedHost(db.Model):
    """
    Managed host
    """
    __tablename__ = 'managedhost'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Text, index=True)
    hostname = db.Column(db.Text, index=True)

    users = relationship("ManagedUser", back_populates="host")
    managers = relationship(
        "Manager",
        secondary=association_Manager_ManagedHost,
        back_populates="hosts"
    )

    def __repr__(self):
        return f"<ManagedHost id:{self.id}, uuid: {self.uuid}, hostname={self.hostname}>"


class ManagedUser(db.Model):
    """
    Managed user
    """
    __tablename__ = 'manageduser'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Text, index=True)
    login = db.Column(db.Text, index=True)

    host_id = db.Column(db.Integer, db.ForeignKey('managedhost.id'))
    host = relationship("ManagedHost", back_populates="users")

    def __repr__(self):
        return f"<ManagedUser id:{self.id}, uuid: {self.uuid}, login={self.login}@{repr(self.host)}>"
