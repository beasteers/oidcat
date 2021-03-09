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
        super().__init__()
        self.access = Access(
            well_known_url, username, password, client_id, client_secret, sess=self, **kw)
        self._inject_token = inject_token
        self._token_key = token_key

    def request(self, *a, token=..., **kw):
        if token == ...:
            token = self._inject_token
        if token:
            tkn = self.access.require()
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

class Access:
    def __init__(self, url, username=None, password=None,
                 client_id='admin-cli', client_secret=None,
                 token=None, refresh_token=None, refresh_buffer=0, login=True,
                 sess=None, _wk=None, ask=False, store=False, store_pass=False):
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
            token = cfg.get('token')
            refresh_token = cfg.get('refresh_token')
            self.username = self.username or cfg.get('username')
            self.password = self.password or cfg.get('password')
            if self.store_pass:
                cfg['username'] = self.username
                cfg['password'] = self.password

            self.well_known = cfg['well_known'] = WellKnown(
                _wk or cfg.get('well_known') or get_well_known(url),
                client_id=client_id, client_secret=client_secret,
            )

        self.token = Token.astoken(token, refresh_buffer) if token else None
        self.refresh_token = Token.astoken(refresh_token) if refresh_token else None
        if login and not self.refresh_token and self.username and self.password:
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

    def login(self, username=None, password=None, ask=None, offline=False):
        ask = self.ask if ask is None else ask
        username = self.username = (
            username or self.username or ask and util.ask(Qs.USERNAME))
        password = self.password = (
            password or self.password or ask and util.ask(Qs.PASSWORD, secret=True))
        if not username and not self.refresh_token:
            raise ValueError('Username not provided for login at {}'.format(
                self.well_known['token_endpoint']))

        if self.refresh_token:
            self.token, self.refresh_token = self.well_known.refresh_token(
                self.refresh_token, self.refresh_buffer)
        else:
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
        self.well_known.end_session(self.token, self.refresh_token)
        self.token = self.refresh_token = None
        if self.store:
            with util.saveddict(self.store) as cfg:
                cfg['token'] = cfg['refresh_token'] = None
                cfg['username'] = cfg['password'] = None

    def configure(self, clear=False, **kw):
        if self.store:
            with util.saveddict(self.store) as cfg:
                if clear:
                    cfg.clear()
                cfg.update(kw)

    def user_info(self):
        return self.well_known.userinfo(self.require())

    def token_info(self):
        return self.well_known.tokeninfo(self.require())
