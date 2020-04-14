import os
import html
import uuid
import re

from flask import redirect, request, url_for, abort, render_template

from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests

from flaskapp import app, db, models, forms

import json

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
client = WebApplicationClient(GOOGLE_CLIENT_ID)

login_manager = LoginManager()
login_manager.init_app(app)


def validate_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str)
    except ValueError:
        abort(404, 'Invalid uuid given: {user_uuid}')

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@login_manager.user_loader
def load_user(user_id):
    return models.Manager.query.filter_by(id=user_id).first()


@app.route("/")
def webroot():
    if not current_user.is_authenticated:
        user = models.Manager.query.filter_by(email='nsmirnov@gmail.com').first()
        login_user(user, remember=True)
        return redirect(url_for("webroot"))

        rv = '<a class="button" href="/login">Google Login</a>'
        return rv
    else:
        rv = f'<p>Hello, {current_user.name}! You\'re logged in! Email: {current_user.email}</p>' \
             f'<p><a class="button" href="/logout">Logout</a></p>' \
             f'<p>current_user: {html.escape(repr(current_user))}</p>'
        hosts_with_users = [x for x in current_user.hosts if len(x.users)]
        if not len(hosts_with_users):
            rv += f'<p>No managed hosts with users found</p>'
        else:
            rv += f'<p>Managed hosts and users:</br>'
            for host in hosts_with_users:
                rv += f'&nbsp;&nbsp;' + html.escape(str(host)) + "<br>"
                for user in host.users:
                    rv += f'&nbsp;&nbsp;&nbsp;&nbsp;<a class="button" href="/time/{str(user.uuid)}">' + html.escape(str(user)) + "</a><br>"
            rv += '</p>'
        return rv


@app.route("/time/<user_uuid>", methods=['GET', 'POST'])
@login_required
def time_for_user(user_uuid):
    validate_uuid(user_uuid)
    user = models.ManagedUser.query.filter_by(uuid=user_uuid).first()
    if not user or current_user not in user.host.managers:
        abort(404, 'No user found with given id and managed by you')
    form = forms.TimeForm(useruuid=user_uuid, username=str(user))
    if form.validate_on_submit():
        amount = form.amount.data
        override = models.TimeOverride(amount=amount, status=models.TimeOverrideStatusQueued,
                                       user=user, owner=current_user)
        db.session.add(override)
        db.session.commit()
        rv = f'Time override added for {user}, amount={amount}<br>'
        rv += f'<a class="button" href="{url_for("webroot")}">Home</a>'
        return rv
    return render_template('time.html', title='Time Override', form=form, username=str(user))


@app.route("/rest/overrides/<host_uuid>")
def overrides_for_host(host_uuid):
    """
    REST: Fetch all time overrides for given host
    Authentication is not required
    :param host_uuid:
    :return: hash: { login: amount, ... }
    """
    validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host:
        abort(404, 'No host found with given id')
    overrides = {}
    for user in host.users:
        for override in [x for x in user.timeoverrides if x.status == models.TimeOverrideStatusQueued]:
            login = user.login.lower()
            if login not in overrides:
                overrides[login] = 0
            overrides[login] += override.amount
    return overrides


@app.route("/rest/overrides_ack/<host_uuid>")
def overrides_ack_for_host(host_uuid):
    """
    REST: Acknowledge time overrides for host.
    Call after applying overrides on host.
    :param host_uuid:
    :return: { success: True }
    """
    validate_uuid(host_uuid)
    host = models.ManagedHost.query.filter_by(uuid=host_uuid).first()
    if not host:
        abort(404, 'No host found with given id')
    for user in host.users:
        for override in [x for x in user.timeoverrides if x.status != models.TimeOverrideStatusQueued]:
            db.session.delete(override)
        for override in [x for x in user.timeoverrides if x.status == models.TimeOverrideStatusQueued]:
            override.status = models.TimeOverrideStatusApplied
    db.session.commit()
    return { 'success': True }


@app.route("/user")
@login_required
def user():
    """
    Info about currently logged-in user (manager)
    """
    return f"current_user: {html.escape(str(current_user))}"


@app.route("/login")
def login():
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
def callback():
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
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided by Google
    user = models.Manager.query.filter_by(ext_auth_id=unique_id, ext_auth_type=models.ExtAuthTypeGoogleAuth).first()
    if user:
        if user.name != users_name: user.name = users_name
        if user.email != users_email: user.email = users_email
        if user.picture != picture: user.picture = picture
    else:
        user = models.Manager(ext_auth_id=unique_id, ext_auth_type=models.ExtAuthTypeGoogleAuth, name=users_name, email=users_email, picture=picture)
        db.session.add(user)
    db.session.commit()

    login_user(user, remember=True)

    return redirect(url_for("webroot"))


@app.route("/dump")
@login_required
def dump():
    """
    Dump all known data
    """
    if os.environ.get('APP_ENVIRONMENT', None) != "dev":
        abort(404)
    rv = '<code>'
    rv += "Managers:<br>"
    for manager in models.Manager.query.all():
        rv += html.escape(repr(manager)) + "<br>"
        if len(manager.hosts):
            rv += "&nbsp;&nbsp;Managed hosts:<br>"
            for host in manager.hosts:
                rv += "&nbsp;&nbsp;- " + html.escape(repr(host)) + "<br>"
    rv += "Hosts:<br>"
    for host in models.ManagedHost.query.all():
        rv += html.escape(repr(host)) + "<br>"
        # managers
        if not len(host.managers):
            rv += "&nbsp;&nbsp;(not managed by anyone, isn't it strange?)<br>"
        else:
            rv += "&nbsp;&nbsp;Managed by:<br>"
            for manager in host.managers:
                rv += "&nbsp;&nbsp;- " + html.escape(repr(manager)) + "<br>"
        # users
        if not len(host.users):
            rv += "&nbsp;&nbsp;(no users)"
        else:
            rv += "&nbsp;&nbsp;Managed Users:<br>"
            for user in host.users:
                rv += "&nbsp;&nbsp;- " + html.escape(repr(user)) + "<br>"
                for timeoverride in user.timeoverrides:
                    rv += "&nbsp;&nbsp;&nbsp;&nbsp;- " + html.escape(repr(timeoverride)) + "<br>"
    rv += "</code>"
    return rv


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for("webroot"))


if __name__ == "__main__":
    db.create_all()

    if os.environ.get('APP_ENVIRONMENT', None) == "dev":
        host1 = models.ManagedHost(uuid=str(uuid.uuid1()), hostname='testhost.tld')
        db.session.add(host1)
        host2 = models.ManagedHost(uuid=str(uuid.uuid1()), hostname='otherhost.dom')
        db.session.add(host2)
        user1 = models.ManagedUser(uuid=str(uuid.uuid1()), login="testuser1", host=host1)
        db.session.add(user1)
        user2 = models.ManagedUser(uuid=str(uuid.uuid1()), login="testuser2", host=host1)
        db.session.add(user2)

        host3 = models.ManagedHost(uuid=str(uuid.UUID('59e8368c-7dbc-11ea-923e-7cb0c2957d37')), hostname='john')
        db.session.add(host3)
        user3 = models.ManagedUser(uuid=str(uuid.uuid1()), login="rightrat", host=host3)
        db.session.add(user3)

        manager1 = models.Manager()
        manager1.hosts.append(host1)
        manager1.hosts.append(host2)
        db.session.add(manager1)

        manager2 = models.Manager(ext_auth_type=models.ExtAuthTypeGoogleAuth, ext_auth_id='118295366576899719337', email='nsmirnov@gmail.com')
        manager2.hosts.append(host1)
        manager2.hosts.append(host3)
        db.session.add(manager2)

        db.session.commit()

    if os.environ.get('APP_ENVIRONMENT', None) == "dev":
        app.run(
            host="0.0.0.0",
            debug=True,
            ssl_context=('devcert.crt', 'devcert.key')
        )
    else:
        app.run()
