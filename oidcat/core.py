import os
import threading
import requests
from requests.auth import HTTPBasicAuth
from .token import Token
from .well_known import WellKnown
from . import util, RequestError
from .util import get_well_known



class Session(requests.Session):
    def __init__(self, well_known_url, username=None, password=None,
                 client_id='admin-cli', client_secret=None,
                 inject_token=True, token_key=None, **kw):
        '''A requests.Session object that implicitly handles 0Auth2 authentication
        for services like Keycloak.

        Arguments:
            *a, **kw: See `Access` for information on arguments.
            inject_token (bool): whether to use tokens on all requests by default.
                By default, this is True. To disable/enable on a request by request basis,
                pass `token=False` or `True` depending.
            token_key (str): if you want to pass the request using a query parameter,
                then set this to the key you want to use. Typical value is 'token'.
                By default it will use Bearer Token Authorization.
        '''
        super().__init__()
        self.access = Access(
            well_known_url, username, password, client_id, client_secret, sess=self, **kw)
        self._inject_token = inject_token
        self._token_key = token_key

    def request(self, *a, token=..., **kw):
        if token == ...:
            token = self._inject_token
        if token:
            tkn = token if isinstance(token, Token) else self.access.require()
            if self._token_key:
                kw.setdefault('data', {}).setdefault(self._token_key, str(tkn))
            else:
                kw.setdefault('headers', {}).setdefault("Authorization", "Bearer {}".format(tkn))
        return super().request(*a, **kw)

    def login(self, *a, **kw):
        return self.access.login(*a, **kw)

    def logout(self, *a, **kw):
        return self.access.logout(*a, **kw)


class Qs:
    BASE_HOST = 'What is the base domain of your server (e.g. myapp.com - (assumed services: auth.myapp.com, api.myapp.com))?'
    USERNAME = 'What is your username?'
    PASSWORD = 'What is your password?'


# NOTE: this is separated so that it doesn't get tangled with the Session object and
#       can be reused outside of just requests.
class Access:
    def __init__(self, url, username=None, password=None,
                 client_id='admin-cli', client_secret=None,
                 token=None, refresh_token=None, refresh_buffer=8, login=None,
                 sess=None, _wk=None, ask=False, store=False, store_pass=False):
        '''Controls access, making sure you always have a valid token.

        You must specify one of:
         - username and password - if you specify this, nothing expires.
         - token - this typically has a short lifespan so it's for quick operations where you have the token.
         - refresh_token - if you already have a refresh token, session only lasts the life of a refresh token.

        Arguments:
            url (str): The url for your authentication server.
                e.g. auth.blah.com or https://auth.blah.com/
                     otherrealm@auth.blah.com (specify a specific keycloak realm)
            username (str): your username
            password (str): your password
            client_id (str): the client id to use. By default, it uses `admin-cli`, but this
                doesn't have things like roles, so if you need that, you can create
                a generic public client for one-off scripts.
            client_secret: the client secret. Leave blank for public clients.
            token (str, Token): an access token, if you already have it.
            refresh_token (str, Token): a refresh token that can be used to refresh
                the access token when it expires.
            refresh_buffer (float): the number of seconds prior to expiration
                it should refresh the token. This reduces the chances of a token
                expired error during the handling of the request. It's a balance between
                the reduction of time in a token's lifespan and the amount of time that
                a request typically takes.
                It is set at 8s which is almost always longer than the time between making
                a request and the server authenticating the token (which usually happens
                at the beginning of the route).
            login (bool): whether we should attempt to login. By default, this will be true
                unless only an access token is specified.
            sess (Session): an existing session object.
            ask (bool): if we don't have any valid credentials, should we prompt for
                a username and password? Useful for cli apps.
            store (bool): should we store tokens and urls to disk? (persistance between cli calls)
            store_pass (bool): should we store credentials to disk? (like save your
                username/password forever - UNSAFE)

        '''
        self.sess = sess or requests
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret

        self.refresh_buffer = refresh_buffer
        self.lock = threading.Lock()

        # possibly load token from file
        self.ask = ask
        self.store = os.path.expanduser(store) if store else store
        self.store_pass = store_pass
        with util.saveddict(self.store) as cfg:
            token = cfg.get('token') if token is None else None
            refresh_token = cfg.get('refresh_token') if refresh_token is None else None
            self.username = self.username or cfg.get('username')
            self.password = self.password or cfg.get('password')
            if self.store_pass:
                cfg['username'] = self.username
                cfg['password'] = self.password

            self.well_known = cfg['well_known'] = WellKnown(
                _wk or cfg.get('well_known') or get_well_known(url),
                client_id=client_id, client_secret=client_secret)

        self.token = Token.astoken(token, refresh_buffer) if token is not None else None
        self.refresh_token = Token.astoken(refresh_token) if refresh_token is not None else None

        if login is None:  # by default, handle login depending on inputs
            login = token is None or self.refresh_token is not None
        if login and not self.token and self.username and self.password:
            self.login()

    def __repr__(self):
        return 'Access(\n{})'.format(''.join('  {}={!r},\n'.format(k, v) for k, v in (
            ('username', self.username),
            ('client', self.client_id),
            ('valid', bool(self.token)),
            ('refresh_valid', bool(self.refresh_token)),
            ('token', self.token),
            ('refresh_token', self.refresh_token),
        )))

    def __str__(self):
        return str(self.token)

    def __bool__(self):
        return bool(self.token)

    def require(self):
        '''Retrieve the token, and refresh if it is expired.'''
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

    def login(self, username=None, password=None, ask=None, offline=False):
        '''Login from your authentication provider and acquire a token.'''
        logged_in = False  # in case the refresh token fails
        if self.refresh_token:
            try:
                self.token, self.refresh_token = self.well_known.refresh_token(
                    self.refresh_token, self.refresh_buffer)
                logged_in = bool(self.token)
            except RequestError as e:
                if '(invalid_grant)' not in str(e):
                    raise
                pass  # invalid refresh token - just move on
        
        if not logged_in:
            ask = self.ask if ask is None else ask
            username = self.username = (
                username or self.username or ask and util.ask(Qs.USERNAME))
            password = self.password = (
                password or self.password or ask and util.ask(Qs.PASSWORD, secret=True))
            if not username and not self.refresh_token:
                raise ValueError('Username not provided for login at {}'.format(
                    self.well_known['token_endpoint']))

            self.token, self.refresh_token = self.well_known.get_token(
                username, password, self.refresh_buffer, offline=offline)

        if self.store:
            with util.saveddict(self.store) as cfg:
                cfg['token'] = str(self.token)
                cfg['refresh_token'] = str(self.refresh_token)
                if self.store_pass:
                    cfg['username'] = self.username
                    cfg['password'] = self.password

    def logout(self):
        '''Logout from your authentication provider.'''
        self.well_known.end_session(self.token, self.refresh_token)
        self.token = self.refresh_token = None
        if self.store:
            with util.saveddict(self.store) as cfg:
                cfg['token'] = cfg['refresh_token'] = None
                cfg['username'] = cfg['password'] = None

    def configure(self, clear=False, **kw):
        '''Update the saved information stored on disk.'''
        if self.store:
            with util.saveddict(self.store) as cfg:
                if clear:
                    cfg.clear()
                cfg.update(kw)

    def user_info(self):
        '''Get user info from your authentication provider.'''
        return self.well_known.userinfo(self.require())

    def token_info(self):
        '''Get token info from your authentication provider.'''
        return self.well_known.tokeninfo(self.require())
