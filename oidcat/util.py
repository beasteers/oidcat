import os
import json
import functools
import contextlib
import traceback
import requests
import urllib
from . import RequestError
from .exceptions import safe_format


HOST_KEY = 'VIRTUAL_HOST'
PORT_KEY = 'VIRTUAL_PORT'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8000


def with_well_known_secrets_file(
        url=None, client_id='admin-cli', client_secret=None, realm=None,
        redirect_uris=None, fname=True, well_known=None):
    '''Get a Flask OIDC secrets file from the server's well-known.

    Arguments:
        url (str): the url hostname.
        client_id (str): the client id.
        client_secret (str): the client secret.
        realm (str): the keycloak realm.
        redirect_uris (list): the redirect uris.
        fname (str, bool): The keycloak secrets filename. If not specified,
            it will automatically create a file in ``~/.*_client_secrets/*.json``.
        well_known (dict, None): The existing well-known configuration.

    Returns:
        fname (str): The keycloak secrets filename.
    '''
    wkn = well_known or get_well_known(url, realm)
    return _write_secrets_file(fname, {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "issuer": wkn['issuer'],
            "redirect_uris": _get_redirect_uris(redirect_uris),
            "auth_uri": wkn['authorization_endpoint'],
            "userinfo_uri": wkn['userinfo_endpoint'],
            "token_uri": wkn['token_endpoint'],
            "token_introspection_uri": wkn['introspection_endpoint'],
        }
    })


def with_keycloak_secrets_file(
        url, client_id='admin-cli', client_secret=None, realm=None,
        redirect_uris=None, fname=True):
    '''Create a keycloak secrets file from basic info. Minimizes redundant info.

    Arguments:
        url (str): the url hostname.
        client_id (str): the client id.
        client_secret (str): the client secret.
        realm (str): the keycloak realm.
        redirect_uris (list): the redirect uris.
        fname (str, bool): The keycloak secrets filename. If not specified,
            it will automatically create a file in ``~/.*_client_secrets/*.json``.

    Returns:
        fname (str): The keycloak secrets filename.
    '''
    assert client_id and client_secret, 'You must set a OIDC client id.'
    url = asurl(url)
    realm = realm or 'master'
    realm_url = "{}/auth/realms/{}".format(url, realm)
    oidc_url = '{}/protocol/openid-connect'.format(realm_url)
    return _write_secrets_file(fname, {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "issuer": realm_url,
            "redirect_uris": _get_redirect_uris(redirect_uris),
            "auth_uri": "{}/auth".format(oidc_url),
            "userinfo_uri": "{}/userinfo".format(oidc_url),
            "token_uri": "{}/token".format(oidc_url),
            "token_introspection_uri": "{}/token/introspect".format(oidc_url)
        }
    })


def with_keycloak_secrets_file_from_environment(env=None, url=None, realm=None, fname=None):
    '''Create a keycloak secrets file from basic info + environment. Minimizes redundant info.

    Arguments:
        env (str, Env): the environment variable namespace.
        url (str): the url hostname.
        realm (str): the keycloak realm.
        fname (str, bool): The keycloak secrets filename. If not specified,
            it will automatically create a file in ``~/.*_client_secrets/*.json``.

    Returns:
        fname (str): The keycloak secrets filename.
    '''
    env = env or 'APP'
    if isinstance(env, str):
        env = Env(env)
    return with_keycloak_secrets_file(
        asurl(url or env('AUTH_HOST')), env('CLIENT_ID'), env('CLIENT_SECRET'),
        realm=realm or env('AUTH_REALM') or None,
        redirect_uris=_get_redirect_uris(env('REDIRECT_URIS')),
        fname=fname,
    )


def _write_secrets_file(fname, cfg):
    if not fname:
        return cfg
    if fname is True:
        fname = os.path.expanduser('~/.{}_client_secrets/{}.json'.format(
            __name__.split('.')[0], cfg.get('client_id', 'secrets')))
    fname = os.path.abspath(fname)
    os.makedirs(os.path.dirname(fname), exist_ok=True)
    with open(fname, 'w') as f:
        json.dump(cfg, f, indent=4, sort_keys=True)
    assert os.path.isfile(fname)
    return fname


_WK_PATH = '/auth/realms/{realm}/.well-known/openid-configuration'

def well_known_url(url, realm=None, secure=None):
    '''Prepares a consistent well-known url'''
    path = ''
    if '/.well-known/openid' not in url:
        url, realm = _parse_auth_url(url, realm)
        path = _WK_PATH.format(realm=realm or 'master')
    url = asurl(url, path, secure=secure)
    return url


def _get_redirect_uris(uris=None, **kw):
    '''Gets properly formatted uri's for the server-side secrets file configuration.'''
    uris = aslist(uris)
    if not uris:
        uris = [os.getenv(HOST_KEY) or '{}:{}/*'.format(DEFAULT_HOST, os.getenv(PORT_KEY, str(DEFAULT_PORT)))]
    return [asurl(u, **kw) for u in uris]


@functools.lru_cache()
def get_well_known(url, realm=None, secure=None):
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


def _asitems(itemtype, *othertypes):
    '''A helper meta function that generates casting functions. 
    e.g.: ``aslist = _asitems(list, tuple, set)``'''
    def inner(x):
        return (
            x if isinstance(x, itemtype) else
            itemtype(x) if isinstance(x, othertypes) else
            [x] if x else [])
    name = itemtype.__name__
    inner.__name__ = 'as{}'.format(name)
    inner.__doc__ = '''Convert value to {name}.

    Falsey values becomes an empty {name}.
    Types ({others}) are cast to {name}.
    Everything else becomes a single element {name}.
    '''.format(
        name='``{}``'.format(name), 
        others=', '.join('``{}``'.format(c.__name__) for c in othertypes))
    return inner


aslist = _asitems(list, tuple, set)
as_set = _asitems(set, tuple, list)
astuple = _asitems(tuple, list, set)


def asurl(url, *paths, secure=None, **args):
    '''Given a hostname, convert it to a URL.

    .. code-block:: python

        # schema
        assert oidcat.util.asurl('my.server.com') == 'https://my.server.com'
        assert oidcat.util.asurl('localhost:8080') == 'http://localhost:8080'
        assert oidcat.util.asurl('my.server.com', secure=False) == 'http://my.server.com'

        # adding paths
        assert oidcat.util.asurl('my.server.com', 'something', 'blah') == 'https://my.server.com/something/blah'

        # argument formatting
        assert oidcat.util.asurl('my.server.com', myvar=1, othervar=2) == 'https://my.server.com?myvar=1&othervar=2'
        assert oidcat.util.asurl('my.server.com?existingvar=0#helloimahash', myvar=1, othervar=2) == 'https://my.server.com?existingvar=0&myvar=1&othervar=2#helloimahash'

    Arguments:
        url (str): The hostname. Can start with https?:// or can just be my.domain.com.
        *paths (str): The paths to append to the URL.
        secure (bool): Should we use http or https? If not specified, it will use https (unless it's localhost)
            If it already starts with https?://, then this is ignored.
        **args: query parameters to add to the url.
    '''
    if url:
        if not (url.startswith('http://') or url.startswith('https://')):
            if secure is None:
                secure = not url.startswith('localhost')
            url = 'http{}://{}'.format(bool(secure)*'s', url)
        url = os.path.join(url, *(p.lstrip('/') for p in paths if p))
        # add args, and make sure they go before the hashstring
        args = {k: v for k, v in args.items() if v is not None}
        if args:
            url, hsh = url.split('#', 1) if '#' in url else (url, '')
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(args)
            if hsh:
                url += '#' + hsh
        return url


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


class Env:
    '''Get environment variables. Makes for easy variable namespacing/prefixing.'''
    def __init__(self, prefix=None, upper=True, **kw):
        self.prefix = prefix or ''
        self.upper = upper
        self.vars = kw
        if self.upper:
            self.prefix = self.prefix.upper()

    def __str__(self):
        '''Show the matching environment variables.'''
        return '<env {}>'.format(''.join([
            '\n  {}={}'.format(k, self(k)) for k in self.vars
        ]))

    def __contains__(self, key):
        '''Does that key (plus prefix) exist?'''
        return self.key(key) in os.environ

    def __getattr__(self, key):
        '''Get the environment variable.'''
        return self.get(key)

    def __call__(self, key, default=None, *a, **kw):
        return self.get(key, default, *a, **kw)

    def get(self, key, default=None, cast=None):
        '''Get the environment variable.'''
        y = os.environ.get(self.key(key))
        if y is None:
            return default
        if callable(cast):
            return y
        if y in ('1', '0'):
            y = int(y)
        if y.lower() in ('y', 'n'):
            y = y.lower() == 'y'
        return y

    def gather(self, *keys, **kw):
        '''Get multiple environment variables. You can do it either

        Arguments:
            *keys: the keys to get.
            **kw: if ``*keys`` is empty, these keys to get, also allowing you to rename the keys in the return value. 
                The values will be used to lookup and the keys will be used to rename the variable.
                If ``*keys`` is not empty, ``**kw`` will be passed to ``self.get`` instead.

        Returns:
            values (str, list, dict): if ``len(keys) == 1``, then it will return a single value.
                Otherwise it will return a list. If ``*keys`` are not specified and ``**kw`` is, 
                it will return a dictionary.

        .. code-block:: python

            env = Env('app_')  # we're trying to access: APP_HOST, APP_USERNAME
            assert env.gather('host') == 'myhost.com'
            assert env.gather('host', 'username') == ['myhost.com', 'myusername']
            assert env.gather(url='host', user='username') == {'url': 'myhost.com', 'user': 'myusername'}
        '''
        return (
            (self.get(keys[0], **kw) if len(keys) == 1 else [self.get(k, **kw) for k in keys])
            if keys else {k: self.get(v) for k, v in kw.items()}
        )

    def key(self, x):
        '''Prepare the environment key.'''
        k = (self.prefix or '') + self.vars.get(x, x)
        return k.upper() if self.upper else k

    def all(self):
        '''Get all environment variables that match the prefix.'''
        return {k: v for k, v in os.environ.items() if k.startswith(self.prefix)}

    DELETE = object()

    def set(self, **kw):
        for k, v in kw.items():
            k = self.key(k)
            if v is self.DELETE:
                del os.environ[k]
                continue
            os.environ[k] = str(v)


class Role(list):
    '''Define a set of roles: e.g.

    .. code-block:: python

        r, w, d = Role('read'), Role('write'), Role('delete')
        r.audio + r.any.spl + (r+w).meta + d('audio', 'spl')
        # ['read-audio', 'read-any-spl', 'read-any-meta', 'write-any-meta',
        #  'delete-audio', 'delete-spl']
    '''
    def __init__(self, *xs):
        super().__init__(
            xi for x in xs for xi in (
                [x] if isinstance(x, str) else x))

    def __call__(self, *keys):
        return Role('{}-{}'.format(i, ki) for i in self for k in keys for ki in Role(k))

    def __add__(self, *xs):
        return Role(self, *Role(*xs))

    def __getattr__(self, k):
        return self(k)

    def __radd__(self, x):
        # return Role(x).join(self)  # << idk wtf that was supposed to be
        return Role(x) + self


class Colors(dict):
    '''Color text. e.g.

    To use the builtin colors:

    .. code-block:: python

        print(oidcat.util.color('hi', 'red') + oidcat.util.color.blue('hello') + oidcat.util.color['green']('sup'))
    '''
    def __call__(self, x, name=None):
        if not name:
            return str(x)
        return '\033[{}m{}\033[0m'.format(super().__getitem__(name.lower()), x) if name else x

    def __getitem__(self, k):
        if k not in self:
            raise KeyError(k)
        return functools.partial(self.__call__, name=k)

    def __getattr__(self, k):
        if k not in self:
            raise AttributeError(k)
        return functools.partial(self.__call__, name=k)


color = Colors(
    black='0;30',
    red='0;31',
    green='0;32',
    orange='0;33',
    blue='0;34',
    purple='0;35',
    cyan='0;36',
    lightgray='0;37',
    darkgray='1;30',
    lightred='1;31',
    lightgreen='1;32',
    yellow='1;33',
    lightblue='1;34',
    lightpurple='1;35',
    lightcyan='1;36',
    white='1;37',
)
Colors.__doc__ += '''

Builtin colors:
{}
'''.format('\n'.join(
    ' - ``{}``: ``{}``'.format(k, v)
    for k, v in color.items()
))

color_ = color


def ask(question, color=None, secret=False):
    '''Prompt the user for input.

    .. code-block:: python

        oidcat.util.ask("what's your username?", 'purple')
        oidcat.util.ask("what's your password?", 'purple', secure=True)

    Arguments:
        question (str): the prompt message.
        color (str, None): the color name for the prompt message.
            See ``oidcat.util.color`` for available colors.
        secret (bool): Is the value secret? If yes, it will use a
            password input.
    '''
    prompt = input
    if secret:
        import getpass
        prompt = getpass.getpass
    return prompt(':: {} '.format(color_(question, color)))


@contextlib.contextmanager
def saveddict(fname):
    '''A context manager that lets you store data in a JSON file. This is useful for storing configuration values 
    between runs (great for configuring CLIs).
    If ``fname`` is None, then nothing is saved to file.

    .. code-block:: python

        # you can use either
        fname = None  # this just won't save anything
        fname = 'my/params-file.json'

        with oidcat.util.saveddict(fname) as cfg:
            cfg['host'] = host or cfg.get('host') or SOME_DEFAULT_HOST
            cfg['username'] = (
                username or cfg.get('username') or
                oidcat.util.ask("what's your username?"))
            password = (
                password or cfg.get('password') or
                oidcat.util.ask("what's your password?", secret=True))
            if store_password:  # not very secure !!
                cfg['password'] = password

    '''
    import base64
    try:
        data = {}
        fname = fname and os.path.expanduser(fname)
        if fname and os.path.isfile(fname):
            try:
                with open(fname, 'rb') as f:
                    data = json.loads(base64.b64decode(f.read()).decode('utf-8'))
            except json.decoder.JSONDecodeError:
                pass
        yield data
    finally:
        if fname:
            os.makedirs(os.path.dirname(fname) or '.', exist_ok=True)
            with open(fname, 'wb') as f:
                f.write(base64.b64encode(json.dumps(data).encode('utf-8')))
