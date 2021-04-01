import os
import time
import oidcat


def test_env():
    env = oidcat.util.Env('blahblah_', a='asdfasdf')
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


def test_asurl():
    host = 'meta.bloop.com'
    assert oidcat.util.asurl(host, secure=False) == 'http://{}'.format(host)
    assert oidcat.util.asurl(host, secure=True) == 'https://{}'.format(host)
    assert oidcat.util.asurl(host, 'hi', secure=False) == 'http://{}/hi'.format(host)
    assert oidcat.util.asurl(host, 'hi', secure=True) == 'https://{}/hi'.format(host)
    assert oidcat.util.asurl('http://{}'.format(host), secure=True) == 'http://{}'.format(host)
    assert oidcat.util.asurl('https://{}'.format(host), secure=True) == 'https://{}'.format(host)


def test_aslist():
    assert oidcat.util.aslist(5) == [5]
    assert oidcat.util.aslist([5]) == [5]
    assert oidcat.util.aslist((5,)) == (5,)


def test_color():
    txt = 'asdf'
    assert oidcat.util.color(txt, 'blue') == oidcat.util.color.blue(txt) == '\033[0;34m{}\033[0m'.format(txt)


def test_exceptions():
    out, code, headers = oidcat.exc2response(oidcat.Unauthorized(), asresponse=False)
    assert code == 401
    assert set(out) == {'error', 'message', 'type'}
    assert headers == {'WWW-Authenticate': 'Bearer'}