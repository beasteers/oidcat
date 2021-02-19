import os
import json
import flask
from flask import request
import flask_oidc


import functools, base64


class OpenIDConnect(flask_oidc.OpenIDConnect):
    @functools.wraps(flask_oidc.OpenIDConnect.__init__)
    def __init__(self, app, credentials_store=None, *a, **kw):
        if isinstance(credentials_store, str):
            import sqlitedict
            credentials_store = sqlitedict.SqliteDict(
                credentials_store, autocommit=True)
        super().__init__(app, credentials_store, *a, **kw)


    def accept_token(self, scopes_required=None, keycloak_role=None, client=True,
                     require_token=True, checks=None):
        checks = checks or []

        def wrapper(view_func):
            @functools.wraps(view_func)
            def decorated(*args, **kwargs):
                # get token & check if it's valid
                token = self.get_token_from_request()
                validity = self.validate_token(token, scopes_required, keycloak_role, client, checks)
                if validity is True or not require_token:
                    return view_func(*args, **kwargs)

                # on no! I'm not supposed to talk to strangers!
                return flask.jsonify({
                    'error': 'invalid_token',
                    'error_description': validity
                }), 401, {'WWW-Authenticate': 'Bearer'}
            return decorated
        return wrapper


    def get_token_from_request(self):
        return (
            self._get_bearer_token() or
            request.form.get('access_token') or
            request.args.get('access_token') or
            flask.g.oidc_id_token and self.get_access_token() or None)


    def token_data(self, token=None):
        token = token or self.get_token_from_request() or {}
        if not isinstance(token, dict):
            header, tkn, signature = token.split('.')
            token = json.loads(base64.b64decode(tkn + '==='))
        return token

    def get_access_token(self):
        return super().get_access_token() if flask.g.oidc_id_token else None

    def _get_bearer_token(self):
        auth = request.headers.get('Authorization') or ''
        return auth.split(None,1)[1].strip() if auth.startswith('Bearer ') else None

    def validate_token(self, token, scopes_required=None, keycloak_role=None, client=True, checks=None):
        validity = super().validate_token(token, scopes_required) if token else 'No token'
        if validity is True:
            token_info = self.token_data(token)
            if (not self.has_keycloak_role(keycloak_role, token_info, client=client) or
                    not all(chk(token_info) for chk in checks or ())):
                validity = 'Insufficient privileges.'
        return validity

    def get_roles(self, token=None, client=True):
        token = self.token_data(token)
        # get roles from token
        mode = 'keycloak'  # TODO get this from app config
        if mode in ('keycloak', 'kc'):
            user_roles = token['realm_access']['roles'] if 'realm_access' in token else []
            if client:
                if client is True:
                    client = self.client_secrets['client_id']
                try:
                    user_roles += token['resource_access'][client]['roles']
                except KeyError:
                    pass
        else:
            raise ValueError('Unknown token schema: {!r}'.format(mode))
        return user_roles

    def has_keycloak_role(self, roles, token=None, client=True):
        if not roles:
            return True
        # compare roles
        roles = {roles} if isinstance(roles, str) else set(roles)
        return roles.issubset(set(self.get_roles(token, client=client)))

    # def load_secrets(self, app):  # this is from master, but is not available in the current pip package
    #     # Load client_secrets.json to pre-initialize some configuration
    #     return _json_loads(app.config['OIDC_CLIENT_SECRETS'])

# https://github.com/googleapis/oauth2client/blob/0d1c814779c21503307b2f255dabcf24b2a107ac/oauth2client/clientsecrets.py#L119
# def _json_loads(content):
#     if isinstance(content, dict):
#         return content
#     if os.path.isfile(content):
#         with open(content, 'r') as f:
#             content = f.read()
#     if not isinstance(content, str):
#         content = content.decode('utf-8')
#     return json.loads(content)
