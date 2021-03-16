'''

@oidc.accept_token(keycloak_role='sensor')
def get():
    oidc.require(oidc.token)


'''
import os
import json
import functools
import flask
from flask import request
import flask_oidc
import oidcat
from . import util, Unauthorized, RequestError, exc2response
from .token import Token


class OpenIDConnect(flask_oidc.OpenIDConnect):
    @functools.wraps(flask_oidc.OpenIDConnect.__init__)
    def __init__(self, app=None, credentials_store=None, *a, **kw):
        if isinstance(credentials_store, str):
            import sqlitedict
            credentials_store = sqlitedict.SqliteDict(
                credentials_store, autocommit=True)
        super().__init__(app, credentials_store, *a, **kw)


    def init_app(self, app):
        super().init_app(app)
        app.config.setdefault('OIDC_OAUTH2_PROVIDER', 'keycloak')
        app.errorhandler(RequestError)(exc2response)

    def accept_token(self, scopes=None, role=None, realm_role=None, client_role=None,
                     required=True, checks=None):

        def wrapper(view_func):
            @functools.wraps(view_func)
            def decorated(*a, **kw):
                self.valid_token(*util.aslist(role), scopes=scopes,
                                 realm_role=realm_role, client_role=client_role,
                                 required=required, checks=checks)
                return view_func(*a, **kw)
            return decorated
        return wrapper

    # get token

    @property
    def token(self):
        token = getattr(flask.g, 'oidc_token_obj', None)
        if token is None:
            token = (
                self._get_bearer_token() or
                request.form.get('access_token') or
                request.args.get('access_token') or
                self.get_access_token() or None)
            if token:
                token = Token(token)
            flask.g.oidc_token_obj = token
        return token if token is not None else Token()

    def valid_token(self, *roles, scopes=None, realm_role=None, client_role=None,
                    client_id=True, required=True, checks=None, token=None):
        # check if token is valid
        token = self.token if token is None else Token.astoken(token)
        validity = token.validity
        if validity is True and not token.token:
            validity = 'No token'  # redundant
        if validity is True:
            validity = self.validate_token(token.token, scopes)
        if validity is True:
            # make sure it has one of the required roles, and that all arbitrary checks pass.
            try:
                validity = self.has_role(
                    *roles, realm=realm_role, client=client_role, client_id=client_id,
                    required=True)
            except oidcat.Unauthorized as e:
                validity = str(e)
            if validity is True and not all(chk(token) for chk in checks or ()):
                validity = 'Insufficient privileges.'
        token.valid = True if validity is True else Unauthorized(validity)

        # on no! I'm not supposed to talk to strangers!
        if required and validity is not True:
            raise Unauthorized(validity)
        return token

    def get_access_token(self):
        return super().get_access_token() if flask.g.oidc_id_token else None

    def _get_bearer_token(self):
        auth = request.headers.get('Authorization') or ''
        return auth.split(None,1)[1].strip() if auth.startswith('Bearer ') else None

    # check token

    def has_role(self, *roles, realm=None, client=None, client_id=True, **kw):
        if client_id is True:
            client_id = self.client_secrets['client_id']
        return self.token.has_role(
            *roles, realm=realm, client=client, client_id=client_id,
            mode=flask.current_app.config['OIDC_OAUTH2_PROVIDER'], **kw)

    def require_role(self, *roles, **kw):
        return self.require(self.has_role(*roles, **kw))

    def require(self, test, msg=None):
        if not test:
            raise Unauthorized(msg)


    def load_secrets(self, app):  # this is from master, but is not available in the current pip package
        # Load client_secrets.json to pre-initialize some configuration
        return _json_loads(app.config['OIDC_CLIENT_SECRETS'])

# https://github.com/googleapis/oauth2client/blob/0d1c814779c21503307b2f255dabcf24b2a107ac/oauth2client/clientsecrets.py#L119
def _json_loads(content):
    if isinstance(content, dict):
        return content
    if os.path.isfile(content):
        with open(content, 'r') as f:
            content = f.read()
    if not isinstance(content, str):
        content = content.decode('utf-8')
    return json.loads(content)
