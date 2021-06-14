import os
import time
import oidcat
from unittest.mock import patch
# @patch.dict('os.environ', {'newkey': 'newvalue'})


def test_with_keycloak_secrets_file():
    host = 'auth.domain.com'
    client_id = 'a'
    client_secret = 'b'
    cfg = oidcat.util.with_keycloak_secrets_file(
        host, client_id, client_secret, realm='asdf', fname=None)['web']
    assert cfg['issuer'] == 'https://{}/auth/realms/asdf'.format(host)
    assert cfg['auth_uri'] == 'https://{}/auth/realms/asdf/protocol/openid-connect/auth'.format(host)
    assert cfg['userinfo_uri'] == 'https://{}/auth/realms/asdf/protocol/openid-connect/userinfo'.format(host)
    assert cfg['token_uri'] == 'https://{}/auth/realms/asdf/protocol/openid-connect/token'.format(host)
    assert cfg['token_introspection_uri'] == 'https://{}/auth/realms/asdf/protocol/openid-connect/token/introspect'.format(host)
    assert cfg['client_id'] == client_id
    assert cfg['client_secret'] == client_secret


def test_get_redirect_uris():
    with patch.dict('os.environ', {oidcat.util.HOST_KEY: 'mydomain.com'}):
        assert oidcat.util._get_redirect_uris() == ['https://mydomain.com']
        assert oidcat.util._get_redirect_uris([]) == ['https://mydomain.com']
        assert oidcat.util._get_redirect_uris('otherdomain.com') == ['https://otherdomain.com']
        assert oidcat.util._get_redirect_uris(['otherdomain.com']) == ['https://otherdomain.com']
        assert oidcat.util._get_redirect_uris(['https://otherdomain.com']) == ['https://otherdomain.com']
        assert oidcat.util._get_redirect_uris(['http://otherdomain.com']) == ['http://otherdomain.com']


def tests_well_known_url():
    urlp = 'https://app.com/auth/realms/{}/.well-known/openid-configuration'
    assert oidcat.util.well_known_url('app.com') == urlp.format('master')
    assert oidcat.util.well_known_url('app.com', 'asdf') == urlp.format('asdf')
    assert oidcat.util.well_known_url('asdf@app.com') == urlp.format('asdf')
    assert oidcat.util.well_known_url('asdf@app.com', 'zxcv') == urlp.format('asdf')
    assert oidcat.util.well_known_url('https://asdf@app.com') == urlp.format('asdf')
    assert oidcat.util.well_known_url('http://asdf@app.com') == urlp.format('asdf').replace('https', 'http')
    assert oidcat.util.well_known_url('asdf@app.com', secure=False) == urlp.format('asdf').replace('https', 'http')
    assert oidcat.util.well_known_url(urlp.format('asdf')) == urlp.format('asdf')


def test_env():
    prefix = 'blahblah_'
    env = oidcat.util.Env(prefix, a='asdfasdf')
    k1 = 'blahblah_asdfasdf'.upper()
    assert env.key('a') == k1
    os.environ[k1] = 'qqqqqq'
    assert env('a') == os.environ[k1]

    k2 = 'blahblah_b'.upper()
    os.environ[k2] = 'qqqqqq'
    assert env('b') == os.environ[k2]

    assert env.gather('a') == os.environ[k1]
    assert env.gather('a', 'b') == [os.environ[k1], os.environ[k2]]
    assert env.gather(asdf='a', zxcv='b') == {'asdf': os.environ[k1], 'zxcv': os.environ[k2]}

    env.set(xxx=10)
    assert (prefix + 'xxx').upper() in os.environ
    assert env.xxx == '10'


def test_asurl():
    host = 'meta.bloop.com'
    assert oidcat.util.asurl(host, secure=False) == 'http://{}'.format(host)
    assert oidcat.util.asurl(host, secure=True) == 'https://{}'.format(host)
    assert oidcat.util.asurl(host, 'hi', secure=False) == 'http://{}/hi'.format(host)
    assert oidcat.util.asurl(host, 'hi', secure=True) == 'https://{}/hi'.format(host)
    assert oidcat.util.asurl('http://{}'.format(host), secure=True) == 'http://{}'.format(host)
    assert oidcat.util.asurl('https://{}'.format(host), secure=True) == 'https://{}'.format(host)


def test_aslist():
    assert oidcat.util.aslist(None) == []
    assert oidcat.util.aslist(5) == [5]
    assert oidcat.util.aslist([5]) == [5]
    assert oidcat.util.aslist((5,)) == [5]


def test_color():
    txt = 'asdf'
    assert oidcat.util.color(txt, 'blue') == oidcat.util.color.blue(txt) == '\033[0;34m{}\033[0m'.format(txt)


def test_exceptions():
    out, code, headers = oidcat.exc2response(oidcat.Unauthorized(), asresponse=False)
    assert code == 401
    assert set(out) == {'error', 'message', 'type'}
    assert headers == {'WWW-Authenticate': 'Bearer'}
    out, code, headers = oidcat.exc2response(oidcat.Unauthorized(), asresponse=False, include_tb=True)
    assert set(out) == {'error', 'message', 'type', 'traceback'}

    exc = oidcat.RequestError()
    assert str(exc) == 'error 500'
    exc = oidcat.RequestError(data={'type': 'Excpt', 'message': 'blah'})
    assert str(exc) == 'Excpt: blah'
    exc = oidcat.RequestError(data={'type': 'Excpt', 'message': 'blah', 'traceback': 'asdfasdfasdf'})
    assert str(exc) == 'Excpt: blah\n\nRequest Traceback:\nasdfasdfasdf'

    out, code, headers = oidcat.exc2response(oidcat.Unauthorized(), asresponse=False)
    err = oidcat.RequestError.from_response(out)
    assert 'Unauthorized: Insufficient privileges' in str(err)
