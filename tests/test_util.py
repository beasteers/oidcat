import os
import time
import oidcat


def test_env():
    env = oidcat.util.Env('blahblah_', a='asdfasdf')
    K = 'blahblah_asdfasdf'.upper()
    assert env.key('a') == K
    os.environ[K] = 'qqqqqq'
    assert env('a') == os.environ[K]

    K = 'blahblah_b'.upper()
    os.environ[K] = 'qqqqqq'
    assert env('b') == os.environ[K]


def test_asurl():
    host = 'meta.bloop.com'
    assert oidcat.util.asurl(host, secure=False) == 'http://{}'.format(host)
    assert oidcat.util.asurl(host, secure=True) == 'https://{}'.format(host)
    assert oidcat.util.asurl(host, 'hi', secure=False) == 'http://{}/hi'.format(host)
    assert oidcat.util.asurl(host, 'hi', secure=True) == 'https://{}/hi'.format(host)
    assert oidcat.util.asurl('http://{}'.format(host), secure=True) == 'http://{}'.format(host)
    assert oidcat.util.asurl('https://{}'.format(host), secure=True) == 'https://{}'.format(host)
