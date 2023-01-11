import os
import json
from oidcat.env import Env
from oidcat.util import asurl, as_realm_url
from oidcat.well_known import get_well_known


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
            # "redirect_uris": _get_redirect_uris(redirect_uris),
            "auth_uri": wkn['authorization_endpoint'],
            "userinfo_uri": wkn['userinfo_endpoint'],
            "token_uri": wkn['token_endpoint'],
            "token_introspection_uri": wkn['introspection_endpoint'],
        }
    })


def with_keycloak_secrets_file(
        url, client_id='admin-cli', client_secret=None, realm=None,
        redirect_uris=None, base=None, fname=True):
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
    realm_url = as_realm_url(url, realm=realm, base=base)
    oidc_url = '{}/protocol/openid-connect'.format(realm_url)
    return _write_secrets_file(fname, {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "issuer": realm_url,
            # "redirect_uris": _get_redirect_uris(redirect_uris),
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
        # redirect_uris=_get_redirect_uris(env('REDIRECT_URIS')),
        fname=fname,
    )


# def _get_redirect_uris(uris=None, **kw):
#     '''Gets properly formatted uri's for the server-side secrets file configuration.'''
#     uris = aslist(uris, split=',')
#     if not uris:
#         uris = uris or aslist(os.getenv(HOST_KEY), split=',')
#         uris = uris or ['{}:{}/*'.format(DEFAULT_HOST, os.getenv(PORT_KEY, str(DEFAULT_PORT)))]
#     return [asurl(u, **kw) for u in uris]


# places to store secrets file
HOMEDIR = os.path.expanduser('~')
TMPDIR = os.getenv('TMPDIR') or '/tmp'
SECRETS_PATTERN = '.{name}_clients/{client_id}.json'
# _SECRETS_FNAME = '~/.{}_clients/{}.json'
# _TMP_SECRETS_FNAME = os.path.join(os.getenv('TMPDIR') or '/tmp', '.{}_clients/{}.json')
if HOMEDIR == '/':
    # warnings.warn(
    #     'Home directory was set to {} which is invalid. '
    #     'Defaulting to {} instead.'.format(HOMEDIR, TMPDIR))
    HOMEDIR = TMPDIR


def _write_secrets_file(fname, cfg, use_tmp=True):
    # if a falsey thing was passed as a filename, just return the dict
    if not fname:
        return cfg
    # automatic filename
    if fname is True:

        fname = os.path.join(
            TMPDIR if use_tmp else HOMEDIR, SECRETS_PATTERN.format(
                name=__name__.split('.')[0],
                client_id=cfg.get('client_id', 'secrets')))
    # create file
    fname = os.path.realpath(fname)
    os.makedirs(os.path.dirname(fname), exist_ok=True)
    with open(fname, 'w') as f:
        json.dump(cfg, f, indent=4, sort_keys=True)
    assert os.path.isfile(fname)
    return fname
