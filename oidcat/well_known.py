import requests
from requests.auth import HTTPBasicAuth
from .util import asurl
from . import RequestError, Token


class WellKnown(dict):
    '''Get the well known for an oauth2 server.

    These are equivalent:
     - auth.myproject.com
     - master@auth.myproject.com
     - https://auth.myproject.com/auth/realms/master/.well-known/openid-configuration

    For another realm, you can do:
     - mycustom@auth.myproject.com

     https://auth.myproject.com/auth/realms/master/.well-known/openid-configuration
     {
         "issuer": "https://auth.myproject.com/auth/realms/master",
         "authorization_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/auth",
         "token_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token",
         "token_introspection_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token/introspect",
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
    def __init__(self, url, client_id='admin-cli', client_secret=None, realm=None, sess=None, secure=True):
        self.sess = sess or requests
        self.client_id = client_id
        self.client_secret = client_secret
        if isinstance(url, dict):
            data = url
        else:
            data = check_error(self.sess.get(
                well_known_url(url, realm=realm, secure=secure)
            ).json(), '.well-known')
        super().__init__(data)

    def bearer(self, token=None):
        return {'Authorization': 'Bearer {}'.format(token)} if token else {}

    def get_certs(self):
        return self.sess.get(self['jwks_uri']).json()['keys']

    def userinfo(self, token):
        return check_error(self.sess.post(
            self['userinfo_endpoint'],
            headers=self.bearer(token)
        ).json(), 'user info')

    def tokeninfo(self, token):
        return check_error(self.sess.post(
            self['token_introspection_endpoint'],
            data={'token': str(token)},
            auth=HTTPBasicAuth(self.client_id, self.client_secret),
        ).json(), 'token info')


    # def authorize(self):
    #     pass

    def get_token(self, username, password=None, refresh_buffer=0, offline=False):
        resp = check_error(self.sess.post(
            self['token_endpoint'],
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'password',
                'username': username,
                'password': password,
                **({'scope': 'offline_access'} if offline else {})
            }).json(), 'access token')
        token = Token(resp['access_token'], refresh_buffer)
        refresh_token = Token(resp['refresh_token'])
        return token, refresh_token

    def refresh_token(self, refresh_token, refresh_buffer=0):
        resp = check_error(self.sess.post(
            self['token_endpoint'],
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'refresh_token',
                'refresh_token': str(refresh_token),
            }).json(), 'refreshed access token')
        token = Token(resp['access_token'], refresh_buffer)
        refresh_token = Token(resp['refresh_token'])
        return token, refresh_token

    # def register(self):
    #     self.sess.post(self['registration_endpoint']).json()

    def end_session(self, token, refresh_token=None):
        self.sess.post(
            self['end_session_endpoint'],
            data={
                'access_token': str(token) if token is not None else None,
                'refresh_token': str(refresh_token) if refresh_token is not None else None,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            })


def well_known_url(url, realm=None, secure=True):
    if not url.startswith('https://') and not url.startswith('http://'):
        parts = url.split('@', 1)
        url = asurl('{}/auth/realms/{}/.well-known/openid-configuration'.format(
            parts[-1], realm or (parts[0] if len(parts) > 1 else 'master')), secure=secure)
    return url

def check_error(resp, item='request'):
    if 'error' in resp:
        raise RequestError(
            'Error getting {item}: ({error}) {error_description}'.format(item=item, **resp))
    return resp
