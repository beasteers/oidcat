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

import sqlitedict
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
@oidc.accept_token(role='editor')  # client/realm role
def edit():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'you did something!'})

@app.route('/edit')
@oidc.accept_token(role='editor', realm=False)  # client role
def edit():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'you did something!'})


@app.route('/view')
@oidc.accept_token(scopes_required=['reader'])  # client scopes
def view():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'something interesting!'})


@app.route('/ultimatepower')
@oidc.accept_token(role='admin', client=None)  # realm role
def ultimatepower():
    '''This will give a 402 if you don't pass `access_token`.'''
    return flask.jsonify({'message': 'mwahahah!'})


if __name__=='__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)

```

### Changes
 - `Session`
    - add `Access` abstraction which encapsulates the access and refresh tokens, well known, and login/logout logic.
    - the access token is automatically added to requests using the Bearer token method.
        - to disable this on a per-request basis, pass `token=False` to your request method (e.g. `sess.get(..., token=False)`)
        - to disable this for all requests on the object, you can do `Session(..., require_token=False)`
        - and to re-enable it on a per-request basis: `sess.get(..., token=False)`
    - add a `login`/`logout` method (which is a convenience wrapper for the Access object)
 - `token`
    - add a token class which encapsulates the token, token data, and expiration logic
    - a token's truthiness can be used to determine if it needs to be refreshed
    - add token checking function `has_role`
 - `server`:
     - `accept_token` takes additional parameters:
        - `role (str, list)`: roles to check for in the token
        - `client (str, bool, default=True)`: see `has_role`
        - `checks (list of callables)`: you can pass arbitrary

     - `has_role` checks for keycloak roles in the token. right now we just support Keycloak compatible token formats
         - `*roles (tuple[str])`: the roles to compare against
         - `client_id (str, bool, default=True)`: if a string, it will check for roles in that
                 client_id. If True, it will check in the current client. If False/None, it
                 will check for realm roles.

     - `util.with_keycloak_secrets_file`: generate the client secrets file and return the path to it. See usage above.
        - this also handles all of the additional urls (token introspection, etc) from the base url.
