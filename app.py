import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask('Google Login App')
app.secret_key = 'Qk2dDh7bHh3vCr6gFo8bHmI5kDcJs'

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "792334593582-l4sve9e6kmvrbtkdlbqfsd6sa5r4t8r7.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback",
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route('/login')
def login():
    session.clear()
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    session['token'] = credentials.token
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=3,
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")


@app.route('/logout')
def logout():
    requests.post('https://accounts.google.com/o/oauth2/revoke',
                  params={'token': session['token']},
                  headers={'content-type': 'application/x-www-form-urlencoded'})

    return redirect('/')


@app.route('/')
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"


@app.route('/protected_area')
@login_is_required
def protected_area():
    google_id = session["google_id"]
    name = session["name"]
    return f"<center>Protected! <br>{name} <br>{google_id} <br><a href='/logout'><button>Logout</button></a></center>"


if __name__ == "__main__":
    app.run(debug=True)
