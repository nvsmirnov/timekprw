#
# TODO: after posting UI forms there is an option to user to send form again on page reload, need to change it
# TODO: some bug: user logs in via google account, then becomes logged out for now reason
# TODO: need to set some DB size limit upon which there will be red warning on web frontend, such as "please contact maintainer: timekprw@.."
# TODO: some bug there: added manager to host, then failed to login as that manager, probably it tries to create it again
#

import logging
from logging import debug, info, warning, error

logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.DEBUG)  # as I understand, this is required for gcp?

import os
import sys
import html
import uuid
import re
import json
import multiprocessing
import atexit

from flask import redirect, request, url_for, abort, render_template
import flask_migrate

from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests

from app import app, db, models, forms
from app.exceptions import *
from app.whoami import whoami
from app.db_permstore import SyncPriorityDelayed, SyncPriorityNormal, SyncPriorityUrgent

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
        abort(403, f'Invalid uuid given: {html.escape(uuid_str)}')


def new_host_uuid():
    # TODO: this is subject to race condition, but chances are very unlikely
    while True:
        newuuid = str(uuid.uuid1()).lower()
        if not models.ManagedHost.query.filter_by(uuid=newuuid).first():
            return newuuid


def new_user_uuid():
    # TODO: this is subject to race condition, but chances are very unlikely
    while True:
        newuuid = str(uuid.uuid1()).lower()
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
            host = models.ManagedHost(hostname=hostname, uuid=new_host_uuid())
            db.session.add(host)
            current_user.hosts.append(host)
            host.pin_generate()
            db.commit_and_sync()
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
        db.session.delete(host)
        db.commit_and_sync()
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
    db.commit_and_sync()
    return redirect(url_for('ui_host', host_uuid=host_uuid))


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
    db.commit_and_sync()
    return redirect(url_for('ui_host', host_uuid=host_uuid))


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
        db.commit_and_sync()
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
    db.commit_and_sync()
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
        db.commit_and_sync()
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
    db.commit_and_sync()
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
        db.commit_and_sync()
        return render_template('time_added.html', user=user, amount=amount)
    else:
        return render_template('time.html', title='Time Override', form=form, username=str(user))


def rest_check_auth(host, data):
    """
    Check authentication
    :param data: request json
    :return: { "success": True|False (result), "message": message to the client}
    """
    try:
        if "authkey" not in data:
            return {"success": False, "message": "To auth key provided"}
        if host.authkey_check(data["authkey"]):
            return {"success": True}
        else:
            return {"success": False, "message": "Authentication failed"}
    except Exception as e:
        debug(f"got exception {e} in rest_check_auth, trace follows:", exc_info=True)
        return {"success": False, "message": "Internal authentication error"}


@app.route("/rest/host-getauthkey", methods=['POST'])
def rest_host_getauthkey():
    """
    REST: add host with pin and return auth key to client
    Authentication is not required
    :param
    {
        pin: "nnnnnn"
    }
    :return:
    {
        success: "true"|"false",
        message: "Cause of problem if success=false" (optional),
        authkey: assigned authentication key for future authentication
        hostuuid: host uuid
    }
    """
    rv = {"success": False, "message": "Internal error: message is not defined"}
    data = request.get_json()
    if not data:
        return {**rv, "message": "json data expected"}
    if "pin" in data:
        # TODO: this implementation can be brute-forced
        #       what we can do is to require some proof of work from the client
        pin = str(data["pin"])
        hostqry = models.ManagedHost.query.filter_by(pin=pin)
        count = hostqry.count()
        if count == 0:
            return {**rv, "message": "Please provide correct pin, or obtain new pin from server"}
        if count > 1:
            return {**rv, "message": "Internal error, please get another pin and come back"}
        if count != 1:
            return {**rv, "message":
                f"Internal error on server, please report to developer: count={count} and it is not 0,1,>1"}
        host = hostqry.first()
        (authkey_plain, authkey_hash) = host.authkey_generate()
        host.authkey = authkey_hash
        host.authkey_trycount = 0
        host.pin = None
        db.commit_and_sync()
        return {"success": True, "authkey": authkey_plain, "hostuuid": host.uuid}
    else:  # "pin" is not in data
        return {**rv, "message": "pin expected"}
    return {**rv}


@app.route("/rest/overrides/<host_uuid>", methods=['POST'])
def rest_overrides(host_uuid):
    """
    REST: Fetch all time overrides for given host
    :param host_uuid:
    :return:
    {
        success: "true"|"false",
        message: "Cause of problem if success=false" (optional),
        overrides: { login1: amount, login2: amount, ... }
    }
    """
    rv = {"success": False, "message": "Internal error: message is not defined"}

    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host:
        return {**rv, "message": "No host found with given id"}

    data = request.get_json()
    if not data:
        return {**rv, "message": "json data expected"}
    auth_result = rest_check_auth(host, data)
    if not auth_result["success"]:
        return auth_result

    overrides = {}
    for user in host.users:
        for override in [x for x in user.timeoverrides if x.status == models.TimeOverrideStatusQueued]:
            login = user.login.lower()
            if login not in overrides:
                overrides[login] = 0
            overrides[login] += override.amount
    return {"success": True, "overrides": overrides}


@app.route("/rest/overrides-ack/<host_uuid>", methods=["POST"])
def rest_overrides_ack(host_uuid):
    """
    REST: Acknowledge time overrides for host.
    Call after applying overrides on host.
    :param host_uuid:
    :return: { success: True }
    """
    rv = {"success": False, "message": "Internal error: message is not defined"}

    host_uuid = validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host:
        return {**rv, "message": "No host found with given id"}

    data = request.get_json()
    if not data:
        return {**rv, "message": "json data expected"}
    auth_result = rest_check_auth(host, data)
    if not auth_result["success"]:
        return auth_result

    for user in host.users:
        # clean older overrides
        for override in [x for x in user.timeoverrides if x.status != models.TimeOverrideStatusQueued]:
            db.session.delete(override)
        # change status of last override
        for override in [x for x in user.timeoverrides if x.status == models.TimeOverrideStatusQueued]:
            override.status = models.TimeOverrideStatusApplied
    db.commit_and_sync()
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
        # picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided by Google
    user = models.Manager.query.filter_by(ext_auth_id=unique_id, ext_auth_type=models.ExtAuthTypeGoogleAuth).first()
    if user:
        # update user's data if we already have it
        if user.name != users_name: user.name = users_name
        if user.email != users_email: user.email = users_email
        # if user.picture != picture: user.picture = picture
    else:
        user = models.Manager(ext_auth_id=unique_id, ext_auth_type=models.ExtAuthTypeGoogleAuth, name=users_name,
                              email=users_email)
        db.session.add(user)
    db.commit_and_sync(sync_priority=SyncPriorityDelayed)

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
        return ("Refused to dump data when debug is disabled")

    rv = ''
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


def run_in_child_process(func):
    try:
        p = multiprocessing.Process(target=func)
        debug(f"{whoami()}: starting {func.__name__} in child process")
        p.start()
        debug(f"{whoami()}: waiting for {func.__name__} to finish")
        p.join()
        debug(f"{whoami()}: {func.__name__} finished")
    except Exception as e:
        error(f"Failed to run {func.__name__} as child process: {e} (enable debug for more)")
        debug(f"{whoami()}: exception follows:", exc_info=True)


#@app.after_request
#def app_after_request():
#    """Do delayed sync after request if needed."""
#    # TODO: when commit is waiting for sync, this may be called two times: one after commit, other here
#    #       need to think if this is really needed; the idea was to sync even when there is no activity since last commit...
#    #       but every rest request commits info about client activity, so may be it is the same this call in after_request
#    db.schedule_sync(sync_priority=SyncPriorityDelayed)


@app.before_request
def app_before_request():
    """Get database from permanent storage before request if needed."""
    # note: before_request is called after before_first_request
    if db.db_permstore_instance:
        # if database is empty, then it should be loaded from permanent storage
        if not len(db.engine.table_names()):
            db.db_permstore_instance.get_from_permstore()


@app.before_first_request
def app_init():
    """Get DB from permanent storage if needed. Upgrade database if needed."""
    debug(f"{whoami()} called")
    if db.db_permstore_instance:
        db.db_permstore_instance.get_from_permstore()

    fresh_db = False
    try:
        # baaad hack, but flask_migrate.current() returns nothing, and I don't know how to test if DB is newly created (i.e. sqlite), or existed before
        if not db.engine.dialect.has_table(db.engine, 'alembic_version'):
            # the only reason i know for this is when database is newly created
            # and we definitely should not run db.create_all() before migration!
            fresh_db = True
    except Exception as e:
        error(f"got exception while trying to get db revision: {e} (enable debug for more)")
        debug(f"exception follows:", exc_info=True)

    debug("running db.create_all()")
    db.create_all()
    debug("done db.create_all()")

    try:
        if fresh_db:
            info("This is a fresh database, marking it as latest revision")
            run_in_child_process(flask_migrate.stamp)
        else:
            debug("Trying to perform database migration")
            run_in_child_process(flask_migrate.upgrade)
    except Exception as e:
        error(f"got exception while trying to upgrade db revision: {e} (enable debug for more)")
        debug(f"exception follows:", exc_info=True)

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

            db.commit_and_sync()
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
                manager1 = models.Manager(ext_auth_type=models.ExtAuthTypeGoogleAuth,
                                          ext_auth_id='118295366576899719337', email='nsmirnov@gmail.com')
                manager1.hosts.append(host)
                db.session.add(manager1)
            manager2 = models.Manager.query.filter_by(email='nsmirnov.pda@gmail.com').first()
            if not manager2:
                debug("creating manager nsmirnov.pda@gmail.com")
                manager2 = models.Manager(ext_auth_type=models.ExtAuthTypeGoogleAuth,
                                          ext_auth_id='103494272264223262600', email='nsmirnov.pda@gmail.com')
                manager2.hosts.append(host)
                db.session.add(manager2)
            db.commit_and_sync()
            debug("done creating built-in objects")
            # debug(dumpdata())
    debug(f"{whoami()} finished")


def sync_forcedly_at_exit():
    # note that it may be called many times; as for db.schedule_sync, it checks for pending commits, so it is ok
    info(f"{whoami()} called")
    with app.app_context():
        db.schedule_sync(sync_priority=SyncPriorityUrgent)
# note that when you register atexit hook here (not in main), function may be called few times
# but when you register in main, it will not be registered when running on GCP
atexit.register(sync_forcedly_at_exit)


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
