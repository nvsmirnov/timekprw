import os
import html
import uuid

from flask import redirect, request, url_for, abort

from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests

from flaskapp import app, db, models

import json

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
client = WebApplicationClient(GOOGLE_CLIENT_ID)

login_manager = LoginManager()
login_manager.init_app(app)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@login_manager.user_loader
def load_user(user_id):
    return models.Manager.query.filter_by(id=user_id).first()


@app.route("/")
def webroot():
    if current_user.is_authenticated:
        rv = f'<p>Hello, {current_user.name}! You\'re logged in! Email: {current_user.email}</p>'\
            f'<a class="button" href="/logout">Logout</a>'\
            f'<div><p>Google Profile Picture:</p>'\
            f'<img src="{current_user.picture}" height=32"" alt="Google profile pic"></img></div>'\
            f'current_user: {html.escape(str(current_user))}'
        for user in models.Manager.query.all():
            rv = f"{rv}<br>\n" + html.escape(str(user))
        return rv
    else:
        rv = '<a class="button" href="/login">Google Login</a>'
        rv = f"{rv}<br>\nKnown users (managers):"
        for user in models.Manager.query.all():
            rv = f"{rv}<br>\n"+html.escape(str(user))
        return rv


@app.route("/user")
def user():
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
def dump():
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
        if not len(host.managers):
            rv += "&nbsp;&nbsp;(not managed by anyone, isn't it strange?)<br>"
        else:
            rv += "&nbsp;&nbsp;Managed by:<br>"
            for manager in host.managers:
                rv += "&nbsp;&nbsp;- " + html.escape(repr(manager)) + "<br>"
        if not len(host.users):
            rv += "&nbsp;&nbsp;(no users)"
        else:
            rv += "&nbsp;&nbsp;Managed Users:<br>"
            for user in host.users:
                rv += "&nbsp;&nbsp;- " + html.escape(repr(user)) + "<br>"
    rv += "</code>"
    return rv


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for("webroot"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        host1 = models.ManagedHost(uuid=str(uuid.uuid1()), hostname='testhost.tld')
        db.session.add(host1)
        host2 = models.ManagedHost(uuid=str(uuid.uuid1()), hostname='otherhost.dom')
        db.session.add(host2)
        user1 = models.ManagedUser(uuid=str(uuid.uuid1()), login="testuser1", host=host1)
        db.session.add(user1)
        user2 = models.ManagedUser(uuid=str(uuid.uuid1()), login="testuser2", host=host1)
        db.session.add(user2)
        manager1 = models.Manager()
        db.session.add(manager1)
        manager2 = models.Manager(ext_auth_type=models.ExtAuthTypeGoogleAuth, ext_auth_id='118295366576899719337')
        db.session.add(manager2)
        manager1.hosts.append(host1)
        manager1.hosts.append(host2)
        manager2.hosts.append(host1)
        db.session.commit()
    if os.environ.get('APP_ENVIRONMENT', None) == "dev":
        app.run(
            debug=True,
            ssl_context=('devcert.crt', 'devcert.key')
        )
    else:
        app.run()
