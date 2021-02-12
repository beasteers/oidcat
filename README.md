# oidcat

Simple OIDC.

It's all so confusing, so I wrote a (small) wrapper package around `requests` and `flask-oidc` that provides a (slightly) easier interface to protect and connect to private resources.

I don't have time to wait for PRs to merge in `flask_oidc`, but maybe I'll get some of this merged eventually!

## Install

```bash
pip install oidcat
```

## Usage

### Client
This is a `requests.Session` object that will handle tokens entirely for you. No need to refresh tokens, no need to manually log back in when both your access and refresh tokens expire.

```python
import os
import oidcat

# basic login:
sess = oidcat.Session('auth.myapp.com', os.getenv('USERNAME'), os.getenv('PASSWORD'))

# that's it! all future requests will use the token
# and it will automatically refresh so effectively, it'll never expire!
out = sess.get('https://api.myapp.com/view').json()
```


### Resource Server

Here's an example resource server.

>NOTE: Technically you can do this without creating a client (and omit them in `with_well_known_secrets_file`) and it will use the `admin-cli` client.

```python
import os
import flask
import oidcat.server
import sqlitedict


app = flask.Flask(__name__)
app.config.update(
    # Create the client configuration (makes request to well known url)
    OIDC_CLIENT_SECRETS=oidcat.util.with_well_known_secrets_file(
        'auth.myapp.com', 'myclient', 'supersecret'),

    # or:
    # Create keycloak client configuration (doesn't need request)
    # OIDC_CLIENT_SECRETS=oidcat.util.with_keycloak_secrets_file(
    #     'auth.myapp.com', 'myclient', 'supersecret', 'myrealm'),
)

oidc = oidcat.server.OpenIDConnect(app, credentials_store=sqlitedict.SqliteDict('creds.db', autocommit=True))
# or equivalently:
oidc = oidcat.server.OpenIDConnect(app, 'creds.db')


# various forms of protecting endpoints

@app.route('/')
@oidc.require_login
def index():
    '''This will redirect you to a login screen.'''5
    return flask.jsonify({'message': 'Welcome!'})


# question - what exactly is the difference between these?

@app.route('/edit')
@oidc.accept_token(keycloak_role='editor')  # client role
def edit():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'you did something!'})


@app.route('/view')
@oidc.accept_token(scopes_required='reader')  # client scopes
def view():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'something interesting!'})


@app.route('/ultimatepower')
@oidc.accept_token(keycloak_role='admin', client=None)  # realm role
def ultimatepower():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'mwahahah!'})


if __name__=='__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)

```

### Changes

 - `accept_token` takes additional parameters:
    - `keycloak_role (str, list)`: roles to check for in the token
    - `client (str, bool, default=True)`: see `has_keycloak_role`
    - `checks (list of callables)`: you can pass arbitrary
 -

 - `has_keycloak_role` checks for keycloak roles in the token (in master, but not current release)
     - `role (str, list)`: the roles to compare against
     - `client (str, bool, default=True)`: if a string, it will check for roles in that
             client-id. If True, it will check in the current client. If False/None, it
             will check for realm roles.

 - `util.with_keycloak_secrets_file`: generate the client secrets file and return the path to it. See usage above.
    - this also handles all of the additional urls (token introspection, etc) from the base url.
