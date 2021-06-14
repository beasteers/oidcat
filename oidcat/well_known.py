import requests
from requests.auth import HTTPBasicAuth
from .util import aslist, well_known_url
from . import RequestError, Token


class WellKnown(dict):
    def __init__(self, url, client_id='admin-cli', client_secret=None, 
                 realm=None, sess=None, secure=True,
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
                well_known_url(url, realm=realm, secure=secure)
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
