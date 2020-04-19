import os
import sys
import html
import uuid
import re
import json

from flask import redirect, request, url_for, abort, render_template

from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests

from app import app, db, models, forms
from app.exceptions import *

import logging
from logging import debug, info, warning, error

logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.DEBUG)  # as I understand, this is required for gcp?

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
client = WebApplicationClient(GOOGLE_CLIENT_ID)

login_manager = LoginManager()
login_manager.init_app(app)


def validate_uuid(uuid_str):
    """Check uuid for syntax and return lower case, or abort. Use as obj_uuid=validate_uuid(obj_uuid)"""
    try:
        s = str(uuid.UUID(uuid_str))
        return s.lower()
    except ValueError:
        abort(403, f'Invalid uuid given: {html.escape(user_uuid)}')



def new_host_uuid():
    # TODO: this is subject to race condition, but chances are very unlikely
    while True:
        newuuid = str(uuid.uuid1()).lower()
        if not models.ManagedHost.query.filter_by(uuid=newuuid).first():
            return newuuid


def new_user_uuid():
    # TODO: this is subject to race condition, but chances are very unlikely
    while True:
        newuuid=str(uuid.uuid1()).lower()
        if not models.ManagedUser.query.filter_by(uuid=newuuid).first():
            return newuuid


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@login_manager.user_loader
def load_user(user_id):
    return models.Manager.query.filter_by(id=user_id).first()


@app.route("/")
def webroot():
    if not current_user.is_authenticated:
        if os.environ.get('APP_ENVIRONMENT', None) == "dev":
            # TODO: remove this in prod
            user = models.Manager.query.filter_by(email='nsmirnov@gmail.com').first()
            login_user(user, remember=True)
            return redirect(url_for("webroot"))

    return render_template('main.html', title='Home', current_user=current_user)


@app.route("/host/<host_uuid>")
@login_required
def ui_host(host_uuid):
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    return render_template(
        'host.html',
        title='Unknown host' if not host else host.hostname,
        host=host
    )


@app.route("/host-add", methods=['GET', 'POST'])
@login_required
def ui_host_add():
    try:
        form = forms.HostAddForm()
        if form.validate_on_submit():
            hostname = form.hostname.data
            if not re.match('^[\w\-\.\ ]+$', hostname):
                abort(403, "Bad symbols in hostname")
            for host in current_user.hosts:
                if hostname.lower() == host.hostname.lower():
                    abort(403, f"Host {html.escape(hostname)} already exists among your hosts")
            host=models.ManagedHost(hostname=hostname, uuid=new_host_uuid())
            db.session.add(host)
            current_user.hosts.append(host)
            host.pin_generate()
            db.session.commit()
            return render_template('host.html', title=host.hostname, host=host)
        else:
            return render_template('host-add.html', title='Add host', form=form)
    except TimekprwException as e:
        debug("exception:", exc_info=True)
        abort(403, str(e))


@app.route("/host-rm/<host_uuid>", methods=['GET', 'POST'])
@login_required
def ui_host_rm(host_uuid):
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    form = forms.HostRemoveForm()
    if form.validate_on_submit():
        db.session.remove(host)
        db.session.commit()
        return redirect(url_for("webroot"))
    else:
        return render_template('host-rm.html', title=f'Confirm remove {host.hostname}', host=host, form=form)


@app.route("/host-set-pin/<host_uuid>", methods=['GET'])
@login_required
def ui_host_set_pin(host_uuid):
    """Clear authetication key and set pin"""
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    host.authkey = None
    host.pin_generate()
    db.session.commit()
    return render_template('host.html', title=host.hostname, host=host)


@app.route("/host-deactivate/<host_uuid>", methods=['GET'])
@login_required
def ui_host_deactivate(host_uuid):
    """Clear authentication token and pin"""
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    host.pin = None
    host.authkey = None
    db.session.commit()
    return render_template('host.html', title=host.hostname, host=host)


@app.route("/host-manager-add/<host_uuid>", methods=['GET', 'POST'])
@login_required
def ui_host_manager_add(host_uuid):
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    form = forms.HostAddManagerForm()
    if form.validate_on_submit():
        email = form.email.data
        manager = models.Manager.query.filter(models.Manager.email.ilike(email)).first()
        if manager:
            if host in manager.hosts:
                abort(403, f"Host already managed by {html.escape(email)}")
        else:
            manager = models.Manager(email=email)
            db.session.add(manager)
        manager.hosts.append(host)
        db.session.commit()
        return redirect(url_for("ui_host", host_uuid=host_uuid))
    else:
        return render_template('host-manager-add.html', title=f'Add manager for {host.hostname}', host=host, form=form)


@app.route("/host-manager-rm/<host_uuid>/<manager_id>", methods=['GET', 'POST'])
@login_required
def ui_host_manager_rm(host_uuid, manager_id):
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    manager = models.Manager.query.filter_by(id=manager_id).first()
    if not manager:
        abort(403, 'Did not find such manager')
    if manager == current_user:
        abort(403, 'You cannot remove yourself from managers list')
    if manager not in host.managers:
        abort(403, 'This manager does not manage this host')
    host.managers.remove(manager)
    db.session.commit()
    return redirect(url_for("ui_host", host_uuid=host_uuid))


@app.route("/host-user-add/<host_uuid>", methods=['GET', 'POST'])
@login_required
def ui_host_user_add(host_uuid):
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    form = forms.HostAddUserForm()
    if form.validate_on_submit():
        login = form.login.data
        # TODO: don't know how to query for users of this host with such login name
        existing = [x for x in host.users if x.login.lower() == login.lower()]
        if len(existing):
            abort(403, f"User {login} already exists on host {host.hostname}")
        user = models.ManagedUser(uuid=new_user_uuid(), login=login)
        db.session.add(user)
        host.users.append(user)
        db.session.commit()
        return redirect(url_for("ui_host", host_uuid=host_uuid))
    else:
        return render_template('host-user-add.html', title=f'Add user on {host.hostname}', host=host, form=form)


@app.route("/host-user-rm/<host_uuid>/<user_id>", methods=['GET', 'POST'])
@login_required
def ui_host_user_rm(host_uuid, user_id):
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host or current_user not in host.managers:
        abort(403, 'No host found with given id and managed by you')
    user = models.ManagedUser.query.filter_by(id=user_id).first()
    if not user:
        abort(403, 'Did not find such user')
    if user.host != host:
        abort(403, 'This user does not belong to this host')
    host.users.remove(user)
    db.session.commit()
    return redirect(url_for("ui_host", host_uuid=host_uuid))


@app.route("/time/<user_uuid>", methods=['GET', 'POST'])
@login_required
def ui_time(user_uuid):
    user_uuid = validate_uuid(user_uuid)
    user = models.ManagedUser.query.filter_by(uuid=user_uuid).first()
    if not user or current_user not in user.host.managers:
        abort(403, 'No user found with given id and managed by you')
    form = forms.TimeForm(useruuid=user_uuid, username=str(user))
    if form.validate_on_submit():
        amount = form.amount.data
        override = models.TimeOverride(amount=amount, status=models.TimeOverrideStatusQueued,
                                       user=user, owner=current_user)
        db.session.add(override)
        db.session.commit()
        return render_template('time_added.html', user=user, amount=amount)
    else:
        return render_template('time.html', title='Time Override', form=form, username=str(user))


@app.route("/rest/overrides/<host_uuid>")
def rest_overrides(host_uuid):
    """
    REST: Fetch all time overrides for given host
    Authentication is not required
    :param host_uuid:
    :return:
    {
        success: "true"|"false",
        message: "Cause of problem if success=false" (optional),
        overrides: { login1: amount, login2: amount, ... }
    }
    """
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host:
        return {"success": False, "message": "No host found with given id"}
    overrides = {}
    for user in host.users:
        for override in [x for x in user.timeoverrides if x.status == models.TimeOverrideStatusQueued]:
            login = user.login.lower()
            if login not in overrides:
                overrides[login] = 0
            overrides[login] += override.amount
    return {"success": True, "overrides": overrides}


@app.route("/rest/overrides-ack/<host_uuid>")
def rest_overrides_ack(host_uuid):
    """
    REST: Acknowledge time overrides for host.
    Call after applying overrides on host.
    :param host_uuid:
    :return: { success: True }
    """
    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host:
        return {"success": False, "message": "No host found with given id"}
    for user in host.users:
        # clean older overrides
        for override in [x for x in user.timeoverrides if x.status != models.TimeOverrideStatusQueued]:
            db.session.delete(override)
        # change status of last override
        for override in [x for x in user.timeoverrides if x.status == models.TimeOverrideStatusQueued]:
            override.status = models.TimeOverrideStatusApplied
    db.session.commit()
    return {'success': True}


@app.route("/user")
@login_required
def ui_user():
    """
    Info about currently logged-in user (manager)
    """
    if os.environ.get('APP_ENVIRONMENT', None) != "dev":
        abort(404)
    return f"current_user: <pre>{html.escape(repr(current_user))}</pre>"


@app.route("/login")
def login():
    """Perform authentication with Google Auth"""
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def login_callback():
    """Callback for Google Auth"""
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        #picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided by Google
    user = models.Manager.query.filter_by(ext_auth_id=unique_id, ext_auth_type=models.ExtAuthTypeGoogleAuth).first()
    if user:
        # update user's data if we already have it
        if user.name != users_name: user.name = users_name
        if user.email != users_email: user.email = users_email
        #if user.picture != picture: user.picture = picture
    else:
        user = models.Manager(ext_auth_id=unique_id, ext_auth_type=models.ExtAuthTypeGoogleAuth, name=users_name, email=users_email)
        db.session.add(user)
    db.session.commit()

    login_user(user, remember=True)

    return redirect(url_for("webroot"))


@app.route("/dump")
@login_required
def ui_dump():
    """
    Dump all known data
    """
    if os.environ.get('APP_ENVIRONMENT', None) != "dev":
        abort(404)
    return f'<pre>\n{html.escape(dumpdata())}\n</pre>'


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for("webroot"))


def dumpdata():
    if logging.getLogger().level > logging.DEBUG:
        # the use of this function is really dangerous because it reads all DB at once
        # if DB is large (on production) there will be a problem
        # even if we use it like debug(dumpdata) - when debug is disabled, dumpdata will read all data anyway.
        # so probably if someone enabled debug he
        #   a) probably will not do this on large production DB;
        #   b) understands what he doing
        # anyway all this dumping requires rewrite to not to read all data into memory at once.
        return("Refused to dump data when debug is disabled")

    rv=''
    rv += 'Managers:\n'
    for manager in models.Manager.query.all():
        rv += f'  {repr(manager)}\n'
        if len(manager.hosts):
            rv += f'    Managed hosts:\n'
            for host in manager.hosts:
                rv += f'      - {repr(host)}\n'
    rv += 'Hosts:\n'
    for host in models.ManagedHost.query.all():
        rv += f'  {repr(host)}\n'
        if not len(host.managers):
            rv += "    (not managed by anyone, isn't it strange?)\n"
        else:
            rv += "    Managed by:\n"
            for manager in host.managers:
                rv += f"      - {repr(manager)}\n"
        if not len(host.users):
            rv += "    (no users)\n"
        else:
            rv += "    Managed Users:\n"
            for user in host.users:
                rv += f"      - {repr(user)}\n"
                for timeoverride in user.timeoverrides:
                    rv += f"        - {repr(timeoverride)}\n"
    return rv


def dbupgrade():
    try:
        info(f"in dbupgrade(): started")
        from flask_script import Manager
        from flask_migrate import MigrateCommand
        migratemanager = Manager(app)
        sys.argv = ['flask', 'db', 'upgrade']  # some hacking
        migratemanager.run({'db': MigrateCommand})
    except Exception as e:
        error(f"in dbupgrade(): got exception: {e} (enable debug for more)")
        debug(f"in dbupgrade(): exception follows:", exc_info=True)


@app.before_first_request
def app_init():
    # try to perform DB migration
    # did not found another the way to automate this on GCP
    try:
        from multiprocessing import Process
        p = Process(target=dbupgrade)
        info(f"starting dbupgrade in child process")
        p.start()
        info(f"waiting for dbupgrade to finish")
        p.join()
        info(f"dbupgrade finished")
    except Exception as e:
        error(f"Failed to run dbupgrade: {e} (enable debug for more)")
        debug("exception follows:", exc_info=True)

    debug("running db.create_all()")
    db.create_all()
    debug("done db.create_all()")


    if os.environ.get('APP_ENVIRONMENT', None) == "dev":

        if models.Manager.query.count():
            debug("skipping creation of dev objects - database already has objects")
        else:
            debug("creating dev objects")

            host1 = models.ManagedHost(uuid=new_host_uuid(), hostname='testhost.tld')
            db.session.add(host1)
            host2 = models.ManagedHost(uuid=new_host_uuid(), hostname='otherhost.dom')
            db.session.add(host2)
            user1 = models.ManagedUser(uuid=new_user_uuid(), login="testuser1", host=host1)
            db.session.add(user1)
            user2 = models.ManagedUser(uuid=new_user_uuid(), login="testuser2", host=host1)
            db.session.add(user2)
            manager1 = models.Manager()
            manager1.hosts.append(host1)
            manager1.hosts.append(host2)
            db.session.add(manager1)

            db.session.commit()
            debug("done creating dev objects")


    # TODO: remove this in production
    debug("creating built-in objects")
    host = models.ManagedHost.query.filter_by(uuid='59e8368c-7dbc-11ea-923e-7cb0c2957d37').first()
    if not host:
        debug("creating host")
        host = models.ManagedHost(uuid=str(uuid.UUID('59e8368c-7dbc-11ea-923e-7cb0c2957d37')), hostname='john')
        user = models.ManagedUser(uuid=new_user_uuid(), login='rightrat', host=host)
        db.session.add(user)
        db.session.add(host)
    manager1 = models.Manager.query.filter_by(email='nsmirnov@gmail.com').first()
    if not manager1:
        debug("creating manager nsmirnov@gmail.com")
        manager1 = models.Manager(ext_auth_type=models.ExtAuthTypeGoogleAuth, ext_auth_id='118295366576899719337', email='nsmirnov@gmail.com')
        manager1.hosts.append(host)
        db.session.add(manager1)
    manager2 = models.Manager.query.filter_by(email='nsmirnov.pda@gmail.com').first()
    if not manager2:
        debug("creating manager nsmirnov.pda@gmail.com")
        manager2 = models.Manager(ext_auth_type=models.ExtAuthTypeGoogleAuth, ext_auth_id='103494272264223262600', email='nsmirnov.pda@gmail.com')
        manager2.hosts.append(host)
        db.session.add(manager2)
    db.session.commit()
    debug("done creating built-in objects")

    debug(dumpdata())


if __name__ == "__main__":

    info("starting app")

    if os.environ.get('APP_ENVIRONMENT', None) == "dev":
        app.run(
            host="0.0.0.0",
            debug=True,
            ssl_context=('devcert.crt', 'devcert.key')
        )
    else:
        app.run()
