import datetime
import requests
from requests.auth import HTTPBasicAuth
from .util import get_well_known, RequestError



class Session(requests.Session):
    access_token = refresh_token = None
    expires = refresh_expires = None
    def __init__(self, well_known_url, username, password,
                 client_id='admin-cli', client_secret=None, login=True, refresh_buffer=60,
                 require_token=False, token_key=None):
        super().__init__()
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.well_known = get_well_known(well_known_url)
        self._refresh_buffer = datetime.timedelta(seconds=refresh_buffer)
        self._require_token = require_token
        self._token_key = token_key
        if login and self.username and self.password:
            self.login()

    def login(self, username=None, password=None):
        self.username = username or self.username
        self.password = password or self.password
        if not self.username:
            raise ValueError('Username not provided for login at {}'.format(self.well_known['token_endpoint']))

        body = {'client_id': self.client_id, 'client_secret': self.client_secret}
        response = self.post(
            self.well_known['token_endpoint'],
            data=(
                dict(body, grant_type='refresh_token', refresh_token=self.refresh_token)
                if self.refresh_token else
                dict(body, grant_type='password', username=self.username, password=self.password)
            ), token=False).json()

        if 'error' in response:
            raise RequestError('Error getting access token: '
                               '({error}) {error_description}'.format(**response))

        self.access_token = Token(
            response['access_token'], response['expires_in'], self._refresh_buffer)
        self.refresh_token = Token(
            response['refresh_token'], response['refresh_expires_in'], self._refresh_buffer)

    def logout(self):
        self.post(
            self.well_known['end_session_endpoint'],
            data={
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            }, token=True)

    def require_token(self):
        if not self.access_token:
            self.login()
        return self.access_token

    def user_info(self):
        response = self.post(self.well_known['userinfo_endpoint']).json()
        if 'error' in response:
            raise RequestError('Error getting user info: ({error}) {error_description}'.format(**response))
        return response

    # def token_info(self):
    #     response = self.post(
    #         self.well_known['token_introspection_endpoint'],
    #         data={
    #             'token': self.access_token,
    #             'access_token': self.access_token,
    #             # 'client_id': self.client_id,
    #             # 'client_secret': self.client_secret,
    #         },
    #     ).json()
    #     if 'error' in response:
    #         raise RequestError('Error getting token info: ({error}) {error_description}'.format(**response))
    #     return response

    def _with_token(self, kw):
        if self._token_key:
            kw.setdefault('data', {}).setdefault(self._token_key, self.require_token())
        else:
            kw.setdefault('headers', {}).setdefault("Authorization", "Bearer {}".format(self.require_token()))

    def request(self, *a, token=True, **kw):
        if token:
            self._with_token(kw)
        return super().request(*a, **kw)


class Token(str):
    def __new__(self, token, *a, **kw):  # TypeError: str() argument 2 must be str, not int
        return super().__new__(self, token)

    def __init__(self, token, expires, refresh_buffer=60):
        super().__init__()
        self.token = token
        self.expires = datetime.datetime.now() + datetime.timedelta(seconds=expires)
        self._refresh_buffer = (
            refresh_buffer if isinstance(refresh_buffer, datetime.timedelta) else
            datetime.timedelta(seconds=refresh_buffer))

    def __bool__(self):
        return self.token and self.expires - self._refresh_buffer > datetime.datetime.now()


# class Access:
#     access_token = refresh_token = None
#     def __init__(self, url, username, password, client_id='admin-cli', client_secret=None, refresh_buffer=60, sess=None):
#         self.sess = sess or requests
#         self.username = username
#         self.password = password
#         self.well_known = get_well_known(url)
#         self.client_id = client_id
#         self.client_secret = client_secret
#         self.refresh_buffer = refresh_buffer
#         self.refresh()
#
#     def __str__(self):
#         return str(self.access_token)
#
#     def __bool__(self):
#         self.refresh()
#         return bool(self.access_token)
#
#     def refresh(self):
#         if not self:
#             self.login()
#         return self
#
#     def login(self, username=None, password=None):
#         self.username = username or self.username
#         self.password = password or self.password
#         if not self.username:
#             raise ValueError('Username not provided for login at {}'.format(self.well_known['token_endpoint']))
#
#         response = requests.post(
#             self.well_known['token_endpoint'],
#             data={
#                 'client_id': self.client_id, 'client_secret': self.client_secret,
#                 **(
#                     {'grant_type': 'refresh_token', 'refresh_token': self.refresh_token}
#                     if self.refresh_token else
#                     {'grant_type': 'password', 'username': self.username, 'password': self.password}
#                 )
#             }).json()
#
#         if 'error' in response:
#             raise RequestError('Error getting access token: '
#                                '({error}) {error_description}'.format(**response))
#
#         self.access_token = Token(
#             response['access_token'], response['expires_in'], self.refresh_buffer)
#         self.refresh_token = Token(
#             response['refresh_token'], response['refresh_expires_in'], self.refresh_buffer)
#
#     def logout(self):
#         requests.post(
#             self.well_known['end_session_endpoint'],
#             data={
#                 'access_token': str(self.access_token),
#                 'refresh_token': str(self.refresh_token),
#                 'client_id': self.client_id,
#                 'client_secret': self.client_secret,
#             })


if __name__ == '__main__':
    # sess = requests.Session()
    sess = Session('bea', 'bea', 'auth.master1.sonycproject.com')
    print(sess.access_token)
    print(sess.expires)
    print(sess.refresh_token)
    print(sess.refresh_expires)
    print(sess.user_info())
    # print(sess.token_info())

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
        "registration_endpoint": "https://auth.myproject.com/auth/realms/master/clients-registrations/openid-connect",
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
