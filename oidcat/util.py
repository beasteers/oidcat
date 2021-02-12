import os
import json
import traceback
import requests


HOST_KEY = 'VIRTUAL_HOST'
PORT_KEY = 'VIRTUAL_PORT'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8000


class RequestError(RuntimeError):
    pass



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
        url = as_url('{}/auth/realms/{}/.well-known/openid-configuration'.format(
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


def with_keycloak_secrets_file_from_environment(prefix, url=None, realm=None, fname=None):
    return with_keycloak_secrets_file(
        as_url(url or envv('AUTH_HOST', prefix)),
        envv('CLIENT_ID', prefix),
        envv('CLIENT_SECRET', prefix),
        realm=realm or envv('AUTH_REALM', prefix, 'master'),
        redirect_uris=get_redirect_uris(envv('REDIRECT_URIS', prefix)),
        fname=fname,
    )


def _write_secrets_file(fname, cfg):
    print(fname, cfg)
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




def kmerge(*xs, sep='_'):
    return sep.join(str(x) for x in xs if x)

def envv(k, prefix=None, default=None):
    return os.getenv(kmerge(k, prefix)) or default



def as_url(url, *paths, secure=None):
    if url:
        if not url.startswith('http://') or url.startswith('https://'):
            if secure is None:
                secure = url != 'localhost'
            url = 'http{}://{}'.format(bool(secure)*'s', url)
        return os.path.join(url, *(p.lstrip('/') for p in paths))

def get_redirect_uris(uris=None):
    uris = as_url(uris or os.getenv(HOST_KEY) or '{}:{}/*'.format(DEFAULT_HOST, os.getenv(PORT_KEY, str(DEFAULT_PORT))))
    return uris if isinstance(uris, (list, tuple)) else [uris] if uris else uris


def traceback_html(e):
    return '''{err}<pre><h3>Traceback (most recent call last):</h3><div>{tb}</div><h3>{typename}: {err}</h3></pre>'''.strip().format(
        err=e, tb='<hr/>'.join(traceback.format_tb(e.__traceback__)).strip('\n'),
        typename=type(e).__name__)
