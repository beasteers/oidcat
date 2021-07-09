'''Provides interfaces for querying a server protected by an authorization provider.

.. code-block:: python

    import oidcat

    sess = oidcat.Session(
        'auth.myserver.com', 'myusername', 'mysecretpassword',
        client_id='my-client-id')

    # lets go le$beans les go!
    resp = sess.get('https://api.myserver.com/protected/endpoint')
    resp.raise_for_status()
    data = resp.json()

    print('yay dis some good data:', data)

Whereas with ``requests``, you'd see:

.. code-block:: python

    import requests

    # making just a plain old session object
    sess = requests.Session()

    # trying to access protected endpoints gonna make u sad
    resp = sess.get('https://api.myserver.com/protected/endpoint')
    resp.raise_for_status()  # Raises 401 Unauthorized error
    data = resp.json()  # no data :'(


'''
import os
import json
import threading
import requests
# from requests.auth import HTTPBasicAuth
from .token import Token
from .well_known import WellKnown
from . import util, RequestError, AuthenticationError

# __all__ = ['Session', 'Access']


class Session(requests.Session):
    def __init__(self, auth_url, username=None, password=None,
                 client_id='admin-cli', client_secret=None,
                 inject_token=True, token_key=None, **kw):
        '''A ``requests.Session`` object that implicitly handles 0Auth2 authentication
        for services like Keycloak.

        This behaves exactly like a ``requests.Session`` object, except that it contains a token manager
        and bundles the token in an Authorization header of each request.

        .. note::
            This is just a thin wrapper that incorporates the functionality of the ``Access`` object into python ``requests``.
            This means that it's relatively trivial to extend this code to support other querying libraries
            (though I don't really know if there's a need to cuz I feel like requests covers everything pretty well. Maybe ``urllib``? idk).

        .. code-block:: python

            # create just like requests.Session
            sess = oidcat.Session('auth.myserver.com', 'myusername', 'secretpassword')
            # and everything is auto-magically authenticated !
            sess.get('api.myserver.com/api/something/secret').json()

            # if you don't want to send a token for a specific endpoint (for whatever reason),
            # you can disable it
            sess.get('otherserver.com/i/cant/have/a/token', token=False).json()

            # and if you don't want to add it by default,
            # you can disable automatic token injection
            sess = oidcat.Session(
                'auth.myserver.com', 'myusername', 'secretpassword',
                inject_token=False)

        Arguments:
            *a: See ``Access`` for information on arguments.
            inject_token (bool): whether to use tokens on all requests by default.
                By default, this is True. To disable/enable on a request by request basis,
                pass `token=False` or `True` depending.
            token_key (str): if you want to pass the request using a query parameter,
                then set this to the key you want to use. Typical value is 'token'.
                By default it will use Bearer Token Authorization.
            **kw: See ``Access`` for information on arguments.
        '''
        super().__init__()
        self.access = Access(
            auth_url, username, password, client_id, client_secret, sess=self, **kw)
        self._inject_token = inject_token
        self._token_key = token_key

    def __repr__(self):
        return '<{}({!r})>'.format(self.__class__.__qualname__, self.access)

    def __str__(self):
        return repr(self)

    def request(self, *a, token=None, **kw):
        # check to see if we should use the default behavior
        if token is None:
            token = self._inject_token

        # check if the user disabled the token
        if token is not False:
            if isinstance(token, Token):
                # if the user provided their own token, let them know
                # that it's invalid.
                if not token:
                    raise AuthenticationError('The token provided is invalid: {!r}'.format(token))
            else:
                # otherwise we do our own auto-magic tokens
                token = self.access.require()

            # decide where to put the token in the request
            if self._token_key:
                kw.setdefault('data', {}).setdefault(self._token_key, str(token))
            else:
                kw.setdefault('headers', {}).setdefault("Authorization", "Bearer {}".format(token))

        # finally, make the normal request + token
        return super().request(*a, **kw)

    def login(self, *a, **kw):
        '''Login to the authorization server and get an access token.'''
        return self.access.login(*a, **kw)

    def logout(self, *a, **kw):
        '''Logout of the authorization server.'''
        return self.access.logout(*a, **kw)

    def require_login(self, *a, **kw):
        '''If not logged in, log back in.'''
        return self.access.require(*a, **kw)


class _Qs:
    # BASE_HOST = 'What is the base domain of your server (e.g. myapp.com - (assumed services: auth.myapp.com, api.myapp.com))?'
    HOST = 'What is the url for your authorization server? e.g. auth.myproject.com'
    USERNAME = 'What is your username?'
    PASSWORD = 'What is your password?'


# NOTE: this is separated so that it doesn't get tangled with the Session object and
#       can be reused outside of just requests.

class Access:
    # _discard_credentials = False
    def __init__(self, url, username=None, password=None,
                 client_id='admin-cli', client_secret=None,
                 token=None, refresh_token=None,
                 refresh_buffer=8, refresh_token_buffer=20,
                 login=None, offline=None, ask=False,
                 store=False, discard_credentials=False,
                 sess=None, _wk=None):
        '''Controls access, making sure you always have a valid token.

        In order to have authenticated requests, you must specify one of:

        - ``username`` and ``password`` - if you specify this, it will functionally never expire.
          This is because we keep the username and password in memory so that it can be used in scripts that run indefinitely.
        - ``token`` - this typically has a short lifespan so it's for quick operations where you have the token.
          Usually you wouldn't need to do this, but it's possible if you really want to!
        - ``refresh_token`` - if you already have a refresh token, session only lasts the life of a refresh token.
          This is a potentially safer method if you need to run something under a few hours (or whatever your
          refresh token lifespan is).

        A potential other solution for long lived tokens is to use an offline token. You use your
        username and password once and it will get an offline refresh token that can be stored and used
        for extended or indefinite periods of time (depending on your auth server settings).
        To use offline tokens, just use ``offline=True``.

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
            refresh_token_buffer (float): equivalent to `refresh_buffer`, but for the refresh token.
            login (bool): whether we should attempt to login. By default, this will be true
                unless only an access token is specified.
            offline (bool): should we request offline tokens? This lets you have long term
                (potentially indefinite) access without needing a username and password. To pass an
                existing offline token, pass it as ``refresh_token=offline_token``.
            sess (Session): an existing session object.
            ask (bool): if we don't have any valid credentials, should we prompt for
                a username and password? Useful for cli apps.
            store (bool): should we store tokens and urls to disk? (persistance between cli calls)
            discard_credentials (bool): should we discard the credentials after logging in?
                By default, we will keep the last used username and password on the object so
                that we can log back in after the refresh token expires. If this is set to True,
                it means that you will only have automatic access for the lifetime of the
                refresh token. In order to maintain access you would have to call
                ``self.login(username, password)`` to renew the refresh token before it expires.
        '''
        self.sess = sess or requests
        self.client_id = client_id
        self.client_secret = client_secret

        # this is used to make sure that two threads using the same sess object
        # don't both try to re-login at the same time.
        self.login_lock = threading.Lock()

        # (maybe) load saved info from file
        self.store = os.path.expanduser(store) if store else store
        with util.saveddict(self.store) as cfg:
            # see if we have the url stored somewhere
            _wk = _wk or cfg.get('well_known') or url or cfg.get('previous_url')
            if not _wk and ask:
                _wk = url = util.ask(_Qs.HOST)
            if url:
                cfg['previous_url'] = url
            # read cached well-known from config
            self.well_known = cfg['well_known'] = WellKnown(
                _wk or url,
                client_id=client_id,
                client_secret=client_secret,
                refresh_buffer=refresh_buffer,
                refresh_token_buffer=refresh_token_buffer)

            # read tokens from config
            if token is None and refresh_token is None:
                token = cfg.get('token')
                refresh_token = cfg.get('refresh_token') or None

        # tokens
        self.token = Token.astoken(token, refresh_buffer)
        self.refresh_token = Token.astoken(refresh_token, refresh_token_buffer)
        self.offline = (
            'offline_access' in self.refresh_token.get('scope', '')
        ) if offline is None else offline

        # credentials
        self.ask = ask
        self._discard_credentials = discard_credentials
        if not self._discard_credentials:
            self.username = username
            self.password = password

        # login
        if login is None:  # by default, handle login depending on inputs
            login = token is None or self.refresh_token is not None
        if login and not self.token and username and password:
            self.login(username, password)

    def __repr__(self):
        '''Get a comprehensive view of the contents of the Access object.'''
        return 'Access(\n{})'.format(''.join(
            '  {}={!r},\n'.format(k, v) if k.strip() else '\n' for k, v in (
                ('username', self.username),
                ('client', self.client_id),
                ('valid', bool(self.token)),
                ('refresh_valid', bool(self.refresh_token)),
                # ('',''),  # hack for newline
                ('token', self.token),
                # ('',''),  # hack for newline
                ('refresh_token', self.refresh_token),
            )))

    def __str__(self):
        '''Get the token as a string.'''
        return str(self.token)

    def __bool__(self):
        '''Evaluates True if the token is valid.'''
        return bool(self.token)

    def require(self):
        '''Retrieve the token, and refresh if it is expired. This is thread safe !'''
        if not self.token:
            # this way we won't have to engage the lock every time
            # it will only engage when the token expires, and then
            # if the token is there by the time the lock releases,
            # then we don't need to log in.
            # the efficiency of this is based on the assumption that:
            #     (timeof(with lock) + timeof(bool(token)))/token.expiration
            #       < timeof(lock) / dt_call
            # which should almost always be true, because short login tokens
            # are forking awful.
            with self.login_lock:
                if not self.token:
                    self.login()
        return self.token

    def login(self, username=None, password=None, ask=None, offline=None):
        '''Login from your authentication provider and acquire a token.

        Arguments:
            username (str): your username. This value is stored on the object
                so subsequent login calls do not need to present it.
            password (str): your password. This value is stored on the object
                so subsequent login calls do not need to present it.
            ask (bool): if no username/password is present, should we prompt
                for one thru the terminal? By default it will be ``False``,
                unless ``ask=True`` was provided to __init__().
            offline (bool): should we request an offline token? These are usually
                much longer lived and allows you to have long term access without
                having to store a username and password on disk. By default it will
                be ``False``, unless ``offline=True`` was provided to __init__().
        '''
        offline = self.offline if offline is None else offline

        # first check if we can use a refresh token
        logged_in = False  # in case the refresh token fails
        if self.refresh_token:
            try:
                self.token, self.refresh_token = self.well_known.refresh_token(
                    self.refresh_token, offline=offline)
                logged_in = bool(self.token)
            except RequestError as e:
                if '(invalid_grant)' not in str(e):
                    raise
                pass  # invalid refresh token - just move on

        if not logged_in:  # that didn't work, let's try with username/password
            ask = self.ask if ask is None else ask
            username = username or self.username or ask and util.ask(_Qs.USERNAME)
            password = password or self.password or ask and util.ask(_Qs.PASSWORD, secret=True)
            if not username:
                raise AuthenticationError('No username provided for login at {}'.format(
                    self.well_known['token_endpoint']))

            if not self._discard_credentials:
                self.username, self.password = username, password

            self.token, self.refresh_token = self.well_known.get_token(
                username, password, offline=offline)

        if self.store:
            with util.saveddict(self.store) as cfg:
                cfg['token'] = str(self.token)
                cfg['refresh_token'] = str(self.refresh_token)

    def logout(self):
        '''Logout from your authentication provider.'''
        self.well_known.end_session(self.token, self.refresh_token)
        self.token = self.refresh_token = None
        self.username = self.password = None
        if self.store:
            with util.saveddict(self.store) as cfg:
                cfg['token'] = cfg['refresh_token'] = None
                cfg['username'] = cfg['password'] = None  # making sure

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



def response_json(resp):
    '''Get the json response from the object, and raise if it's an error.
    It also detects 502 Bad Gateway errors which are returned by nginx
    commonly when server configurations change.

    .. code-block:: python

        data = oidcat.response_json(sess.get('blah.com/api/mydata))

    Arguments:
        resp (requests.Response): The API server response.

    Returns:
        data (any): the JSON-decoded response.

    Raises:
        oidcat.RequestError if the response is a ``dict`` and has ``'error' in data``.
    '''
    try:
        data = resp.json()
    except json.decoder.JSONDecodeError as e:
        # can't be parsed as json - so let's see what it gave us
        txt = resp.text
        # 502 Bad Gateway errors are triggered by nginx
        if '502 Bad Gateway' in txt:
            data = {'error': True, 'type': 'BadGateway', 'code': 502, 'message': txt}
        else:
            raise json.decoder.JSONDecodeError(
                'Could not decode response: \n{}'.format(txt), e.doc, e.pos)

    # check for error messages
    if isinstance(data, dict):
        error = data.get('error')
        if error:
            if isinstance(error, str):
                data = {'error': True, 'message': error}
            raise RequestError.from_response(data)
    return data


Session.login.__doc__ = Access.login.__doc__
Session.logout.__doc__ = Access.logout.__doc__
Session.require_login.__doc__ = Access.require.__doc__
