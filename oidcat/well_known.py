import functools
import requests
from requests.auth import HTTPBasicAuth
from .util import aslist, as_realm_url
from . import RequestError, Token


class WellKnown(dict):
    def __init__(self, url, client_id='admin-cli', client_secret=None, 
                 realm=None, sess=None, secure=True, base=None,
                 refresh_buffer=0, refresh_token_buffer=0):
        '''A generic interface that encapsulates the information returned from 
        the Well-Known configuration of an authorization server.

        This is meant to be as simple and as state-less as possible.

        Arguments:
            url (str): the authorization server hostname.
                These are equivalent:

                - ``auth.myproject.com``
                - ``master@auth.myproject.com``
                - ``https://auth.myproject.com/auth/realms/master/.well-known/openid-configuration``

                For another realm, you can do:

                - ``mycustom@auth.myproject.com``

            client_id (str): the client ID
            client_id (str): the client secret
            realm (str): the authorization server realm. By default, 'master'.
            secure (bool): Whether https:// or http:// should be added for a 
                url without a schema.
            refresh_buffer (float): the number of seconds prior to expiration
                it should refresh the token. This reduces the chances of a token
                expired error during the handling of the request. It's a balance between
                the reduction of time in a token's lifespan and the amount of time that
                a request typically takes.
                It is set at 8s which is almost always longer than the time between making
                a request and the server authenticating the token (which usually happens
                at the beginning of the route).
            refresh_token_buffer (float): equivalent to `refresh_buffer`, but for the refresh token.
        '''
        self.sess = sess or requests
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_buffer = refresh_buffer
        self.refresh_token_buffer = refresh_token_buffer
        if isinstance(url, dict):
            data = url
        else:
            data = check_error(self.sess.get(
                well_known_url(url, realm=realm, secure=secure, base=base)
            ).json(), '.well-known')
        super().__init__(data)

    def jwks(self):
        '''Get the JSON Web Key certificates. Queries ``wk['jwks_uri']``.'''
        return self.sess.get(self['jwks_uri']).json()['keys']

    def userinfo(self, token):
        '''Get user info from the token string.
        Queries ``wk['userinfo_endpoint']``.'''
        return check_error(self.sess.post(
            self['userinfo_endpoint'],
            headers=bearer(token)
        ).json(), 'user info')

    def tokeninfo(self, token):
        '''Get token info from the token string.
        Queries ``wk['token_introspection_endpoint']``.'''
        return check_error(self.sess.post(
            self['token_introspection_endpoint'],
            data={'token': str(token)},
            auth=HTTPBasicAuth(self.client_id, self.client_secret),
        ).json(), 'token info')

    def get_token(self, username, password=None, offline=False, scope=None):
        '''Login to get the token.'''
        scope = aslist(scope)
        if offline:
            scope.append('offline_access')
        resp = check_error(self.sess.post(
            self['token_endpoint'],
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'password',
                'username': username,
                'password': password,
                **({'scope': scope} if scope else {})
            }).json(), 'access token')
        token = Token(resp['access_token'], self.refresh_buffer)
        refresh_token = Token(resp['refresh_token'], self.refresh_token_buffer)
        return token, refresh_token

    def refresh_token(self, refresh_token, offline=False, scope=None):
        '''Refresh the token.'''
        scope = aslist(scope)
        if offline:
            scope.append('offline_access')
        resp = check_error(self.sess.post(
            self['token_endpoint'],
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'refresh_token',
                'refresh_token': str(refresh_token),
            }).json(), 'refreshed access token')
        token = Token(resp['access_token'], self.refresh_buffer)
        refresh_token = Token(resp['refresh_token'], self.refresh_token_buffer)
        return token, refresh_token

    # def register(self):
    #     self.sess.post(self['registration_endpoint']).json()

    def end_session(self, token, refresh_token=None):
        '''Logout.'''
        self.sess.post(
            self['end_session_endpoint'],
            data={
                'access_token': str(token) if token is not None else None,
                'refresh_token': str(refresh_token) if refresh_token is not None else None,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            })


def check_error(resp, item='request'):
    if 'error' in resp:
        try:
            err_msg = '({error}) {error_description}'.format(**resp)
        except KeyError:
            err_msg = str(resp)
        raise RequestError('Error getting {}: {}'.format(item, err_msg))
    return resp


def bearer(token=None):
    '''Get bearer token headers for authenticated request.'''
    return {'Authorization': 'Bearer {}'.format(token)} if token else {}


WellKnown.bearer = staticmethod(bearer)


def well_known_url(url, realm=None, secure=None, base='') -> str:
    '''Prepares a consistent well-known url'''
    if '/.well-known/openid' not in url:
        url, realm = _parse_auth_url(url, realm)
        url = as_realm_url(
            url, '.well-known/openid-configuration', 
            realm=realm, base=base, secure=secure)
    return url


@functools.lru_cache()
def get_well_known(url, realm=None, secure=None) -> dict:
    '''Get the well known for an oauth2 server.

    These are equivalent:
     - auth.myproject.com
     - master@auth.myproject.com
     - https://auth.myproject.com/auth/realms/master/.well-known/openid-configuration

    For another realm, you can do:
     - mycustom@auth.myproject.com

    .. code-block:: python

        # https://auth.myproject.com/auth/realms/master/.well-known/openid-configuration
        {
            "issuer": "https://auth.myproject.com/auth/realms/master",
            "authorization_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/auth",
            "token_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token",
            "token_introspection_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token/introspect",
            "introspection_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token/introspect"
            "userinfo_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/userinfo",
            "end_session_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/logout",
            "jwks_uri": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/certs",
            "registration_endpoint": "https://auth.myproject.com/auth/realms/master/clients-registrations/openid-connect",

            "check_session_iframe": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/login-status-iframe.html",
            "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password", "client_credentials"],
            "response_types_supported": ["code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512", "PS256", "PS512", "RS512"],
            "id_token_encryption_alg_values_supported": ["RSA-OAEP", "RSA1_5"],
            "id_token_encryption_enc_values_supported": ["A128GCM", "A128CBC-HS256"],
            "userinfo_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512", "PS256", "PS512", "RS512", "none"],
            "request_object_signing_alg_values_supported": ["PS384", "ES384", "RS384", "ES256", "RS256", "ES512", "PS256", "PS512", "RS512", "none"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic", "client_secret_post", "tls_client_auth", "client_secret_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "ES256", "RS256", "ES512", "PS256", "PS512", "RS512"],
            "claims_supported": ["aud", "sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email", "acr"],
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": false,
            "scopes_supported": ["openid", "address", "email", "microprofile-jwt", "offline_access", "phone", "profile", "roles", "web-origins"],
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            "code_challenge_methods_supported": ["plain", "S256"],
            "tls_client_certificate_bound_access_tokens": true,
        }

    '''
    url = well_known_url(url, realm, secure=secure)
    resp = requests.get(url).json()
    if 'error' in resp:
        raise RequestError('Error getting .well-known: {}'.format(resp['error']))
    return resp


def _parse_auth_url(url, realm=None):
    '''Parses an optional realm parameter out of a url. e.g. myrealm@auth.domain.com'''
    # split off schema
    prefix = None
    parts = url.split('://', 1)
    if len(parts) > 1:
        prefix, url = parts

    # split off realm
    parts = url.split('@', 1)
    realm = (parts[0] if len(parts) > 1 else realm)
    url = parts[-1]

    # put it back together
    if prefix:
        url = '{}://{}'.format(prefix, url)
    return url, realm
