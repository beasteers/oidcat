import os
import json
import functools
import contextlib
import traceback
import requests
import urllib
from . import RequestError


HOST_KEY = 'VIRTUAL_HOST'
PORT_KEY = 'VIRTUAL_PORT'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8000


@functools.lru_cache()
def get_well_known(url, realm=None, secure=None):
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
    if not url.startswith('https://'):
        parts = url.split('@', 1)
        url = asurl('{}/auth/realms/{}/.well-known/openid-configuration'.format(
            parts[-1], realm or (parts[0] if len(parts) > 1 else 'master')), secure=secure)

    resp = requests.get(url).json()
    if 'error' in resp:
        raise RequestError('Error getting .well-known: {}'.format(resp['error']))
    return resp


def with_well_known_secrets_file(
        url=None, client_id='admin-cli', client_secret=None, realm=None,
        redirect_uris=None, fname=True, well_known=None):
    wkn = well_known or get_well_known(url, realm)
    return _write_secrets_file(fname, {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "issuer": wkn['issuer'],
            "redirect_uris": get_redirect_uris(redirect_uris),
            "auth_uri": wkn['authorization_endpoint'],
            "userinfo_uri": wkn['userinfo_endpoint'],
            "token_uri": wkn['token_endpoint'],
            "token_introspection_uri": wkn['introspection_endpoint'],
        }
    })


def with_keycloak_secrets_file(
        url, client_id='admin-cli', client_secret=None, realm='master',
        redirect_uris=None, fname=True):
    assert client_id and client_secret, 'You must set a OIDC client id.'
    realm_url = "{}/auth/realms/{}".format(url, realm)
    oidc_url = '{}/protocol/openid-connect'.format(realm_url)
    return _write_secrets_file(fname, {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "issuer": realm_url,
            "redirect_uris": get_redirect_uris(redirect_uris),
            "auth_uri": "{}/auth".format(oidc_url),
            "userinfo_uri": "{}/userinfo".format(oidc_url),
            "token_uri": "{}/token".format(oidc_url),
            "token_introspection_uri": "{}/token/introspect".format(oidc_url)
        }
    })


def with_keycloak_secrets_file_from_environment(env=None, url=None, realm=None, fname=None):
    env = env or 'APP'
    if isinstance(env, str):
        env = Env(env)
    return with_keycloak_secrets_file(
        asurl(url or env('AUTH_HOST')), env('CLIENT_ID'), env('CLIENT_SECRET'),
        realm=realm or env('AUTH_REALM', 'master'),
        redirect_uris=get_redirect_uris(env('REDIRECT_URIS')),
        fname=fname,
    )


def _write_secrets_file(fname, cfg):
    if not fname:
        return cfg
    if fname is True:
        fname = os.path.expanduser('~/.{}_client_secrets/{}.json'.format(__name__.split('.')[0], cfg.get('client_id', 'secrets')))
    fname = os.path.abspath(fname)
    os.makedirs(os.path.dirname(fname), exist_ok=True)
    with open(fname, 'w') as f:
        json.dump(cfg, f, indent=4, sort_keys=True)
    assert os.path.isfile(fname)
    return fname




# def kmerge(*xs, sep='_'):
#     return sep.join(str(x) for x in xs if x)

# def envv(k, prefix=None, default=None):
#     return os.getenv(kmerge(k, prefix)) or default

def aslist(x):
    return x if isinstance(x, (list, tuple)) else [x] if x else []


def asurl(url, *paths, secure=None, **args):
    if url:
        if not (url.startswith('http://') or url.startswith('https://')):
            if secure is None:
                secure = url != 'localhost'
            url = 'http{}://{}'.format(bool(secure)*'s', url)
        url = os.path.join(url, *(p.lstrip('/') for p in paths))
        # add args, and make sure they go before the hashstring
        args = {k: v for k, v in args.items() if v is not None}
        if args:
            url, hsh = url.split('#', 1) if '#' in url else (url, '')
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(args)
            if hsh:
                url += '#' + hsh
        return url
as_url = asurl  # backwards compat

def get_redirect_uris(uris=None):
    uris = asurl(uris or os.getenv(HOST_KEY) or '{}:{}/*'.format(DEFAULT_HOST, os.getenv(PORT_KEY, str(DEFAULT_PORT))))
    return uris if isinstance(uris, (list, tuple)) else [uris] if uris else uris


# def traceback_html(e):
#     return '''{err}<pre><h3>Traceback (most recent call last):</h3><div>{tb}</div><h3>{typename}: {err}</h3></pre>'''.strip().format(
#         err=e, tb='<hr/>'.join(traceback.format_tb(e.__traceback__)).strip('\n'),
#         typename=type(e).__name__)




class Env:
    def __init__(self, prefix=None, upper=True, **kw):
        self.prefix = prefix or ''
        self.upper = upper
        self.vars = kw
        if self.upper:
            self.prefix = self.prefix.upper()

    def __str__(self):
        return '<env {}>'.format(''.join([
            '\n  {}={}'.format(k, self(k)) for k in self.vars
        ]))

    def __contains__(self, key):
        return self.key(key) in os.environ

    def __getattr__(self, key):
        return self.get(key)

    def __call__(self, key, default=None, *a, **kw):
        return self.get(key, default, *a, **kw)

    def get(self, key, default=None, cast=None):
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
        return (
            (self.get(keys[0], **kw) if len(keys) == 1 else [self.get(k, **kw) for k in keys])
            if keys else {k: self.get(v) for k, v in kw.items()}
        )

    def key(self, x):
        k = (self.prefix or '') + self.vars.get(x, x)
        return k.upper() if self.upper else k

    def all(self):
        return {k: v for k, v in os.environ.items() if k.startswith(self.prefix)}





class Role(list):
    '''Define a set of roles: e.g.
    >>> r, w, d = Role('read'), Role('write'), Role('delete')
    >>> r.audio + r.any.spl + (r+w).meta + d('audio', 'spl')
    ['read-audio', 'read-any-spl', 'read-any-meta', 'write-any-meta', 'delete-audio', 'delete-spl']
    '''
    def __init__(self, *xs):
        super().__init__(xi for x in xs for xi in ([x] if isinstance(x, str) else x))

    def __call__(self, *keys):
        return Role('{}-{}'.format(i, ki) for i in self for k in keys for ki in Role(k))

    def __add__(self, *xs):
        return Role(self, *Role(*xs))

    __getattr__ = lambda self, k: self(k)
    __radd__ = lambda self, x: Role(x).join(self)

# r, w, d = Role('read'), Role('write'), Role('delete')
# GROUPS = {
#     'sensor-engineer': r.audio + r.any.spl + (r+w+d).any.meta,
#     'sensor': w.audio + w.spl + w.status,
#     'agent': r.spl + w('audio', 'spl'),
#     'participant': (r+w+d).audio,
# }





class Colors(dict):
    '''Color text. e.g.
    >>> print(color('hi', 'red') + color.blue('hello') + color['green']('sup'))
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
color_ = color


def ask(question, color=None, secret=False):
    prompt = input
    if secret:
        import getpass
        prompt = getpass.getpass
    return prompt(':: {} '.format(color_(question, color)))


@contextlib.contextmanager
def saveddict(fname):
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
