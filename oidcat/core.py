import json
import base64
import datetime
import threading
import requests
from requests.auth import HTTPBasicAuth
from .util import get_well_known, RequestError



class Session(requests.Session):
    def __init__(self, well_known_url, username, password,
                 client_id='admin-cli', client_secret=None, login=True, refresh_buffer=60,
                 require_token=True, token_key=None):
        super().__init__()
        self.access = Access(
            well_known_url, username, password, client_id, client_secret,
            login=login, refresh_buffer=refresh_buffer, sess=self)
        self._require_token = require_token
        self._token_key = token_key

    def request(self, *a, token=..., **kw):
        if token == ...:
            token = self._require_token
        if token:
            tkn = self.access.require()
            if self._token_key:
                kw.setdefault('data', {}).setdefault(self._token_key, tkn)
            else:
                kw.setdefault('headers', {}).setdefault("Authorization", "Bearer {}".format(tkn))
        return super().request(*a, **kw)



class Token(str):
    def __new__(self, token, *a, **kw):  # TypeError: str() argument 2 must be str, not int
        return super().__new__(self, token)

    def __init__(self, token, expires, buffer=60):
        super().__init__()
        self.token = token
        self.expires = datetime.datetime.now() + datetime.timedelta(seconds=expires)
        self.buffer = (
            buffer if isinstance(buffer, datetime.timedelta) else
            datetime.timedelta(seconds=buffer))

        header, tkn, self.signature = self.token.split('.')
        self.header = json.loads(base64.b64decode(header + '==='))
        self.data = json.loads(base64.b64decode(tkn + '==='))

    @property
    def time_left(self):
        return self.expires - datetime.datetime.now()

    def __bool__(self):
        return self.token and self.time_left > self.buffer



class Access:
    token = refresh_token = None
    def __init__(self, url, username, password, client_id='admin-cli', client_secret=None,
                 refresh_buffer=60, login=None, sess=None):
        self.sess = sess or requests
        self.username = username
        self.password = password
        self.well_known = get_well_known(url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_buffer = refresh_buffer
        self.lock = threading.Lock()
        if login and self.username and self.password:
            self.login()

    def __str__(self):
        return str(self.token)

    def __bool__(self):
        return bool(self.token)

    def require(self):
        if not self.token:
            # this way we won't have to engage the lock every time
            # it will only engage when the token expires, and then
            # if the token is there by the time the lock releases,
            # then we don't need to log in.
            # the efficiency of this is based on the assumption that:
            #     (timeof(with lock) + timeof(bool(token)))/token.expiration
            #       < timeof(lock) / dt_call
            # which should almost always be true, because short login tokens are forking awful.
            with self.lock:
                if not self.token:
                    self.login()
        return self.token

    def bearer(self):
        return 'Bearer {}'.format(self.require())

    def login(self, username=None, password=None, store=True):
        if store:
            username = self.username = username or self.username
            password = self.password = password or self.password
        if not username:
            raise ValueError('Username not provided for login at {}'.format(
                self.well_known['token_endpoint']))

        resp = self.sess.post(
            self.well_known['token_endpoint'],
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                **({
                    'grant_type': 'refresh_token',
                    'refresh_token': self.refresh_token,
                } if self.refresh_token else {
                    'grant_type': 'password',
                    'username': username,
                    'password': password,
                })
            }, token=False).json()

        if 'error' in resp:
            raise RequestError('Error getting access token: '
                               '({error}) {error_description}'.format(**resp))

        self.token = Token(resp['access_token'], resp['expires_in'], self.refresh_buffer)
        self.refresh_token = Token(resp['refresh_token'], resp['refresh_expires_in'])

    def logout(self):
        self.sess.post(
            self.well_known['end_session_endpoint'],
            data={
                'access_token': str(self.token),
                'refresh_token': str(self.refresh_token),
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            })
        self.token = self.refresh_token = None

    def user_info(self):
        resp = self.sess.post(self.well_known['userinfo_endpoint'], token=True).json()
        if 'error' in resp:
            raise RequestError('Error getting user info: ({error}) {error_description}'.format(**resp))
        return resp

    def token_info(self):
        token = self.require()
        resp = self.sess.post(
            self.well_known['token_introspection_endpoint'],
            data={'token': token}, token=False,
            auth=HTTPBasicAuth(self.client_id, self.client_secret),
        ).json()
        if 'error' in resp:
            raise RequestError('Error getting token info: ({error}) {error_description}'.format(**resp))
        return resp



if __name__ == '__main__':
    # sess = requests.Session()
    sess = Session('boop', 'boop', 'auth.master1.sonycproject.com')
    print(sess.access.token)
    print(sess.access.token.expires)
    print(sess.access.token.data)
    print(sess.access.refresh_token)
    print(sess.access.refresh_token.expires)
    print(sess.access.user_info())
    # print(sess.access.token_info())

    # sess.logout()
    # try:
    #     sess.user_info()
    # except RequestError as e:
    #     print('({}) {}'.format(type(e).__name__, e))


    '''
    https://auth.myproject.com/auth/realms/master/.well-known/openid-configuration
    {
        "issuer": "https://auth.myproject.com/auth/realms/master",
        "authorization_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/auth",
        "token_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token",
        "token_introspection_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token/introspect",
        "introspection_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/token/introspect"
        "userinfo_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/userinfo",
        "end_session_endpoint": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/logout",
        "jwks_uri": "https://auth.myproject.com/auth/realms/master/protocol/openid-connect/certs",

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
