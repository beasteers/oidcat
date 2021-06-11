import os
import pytest

import oidcat
import oidcat.server


HOST = os.getenv('KEYCLOAK_HOST') or 'localhost'
CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID') or 'admin-cli'
CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET') or None
TEST_ROLE = os.getenv('KEYCLOAK_ROLE') or 'editor'
TEST_MISSING_ROLE = 'asdfaoinsadfn'
USERNAME = os.getenv('KEYCLOAK_USER') or 'admin'
PASSWORD = os.getenv('KEYCLOAK_PASS') or 'admin'

def getitem2(x, key):
    try:
        return x[key]
    except KeyError:
        if 'error' in x:
            raise oidcat.RequestError.from_response(x)
        raise KeyError("Could not get key '{}' from {}".format(key, x))

def dump(x):
    import json
    return json.dumps(x, indent=4, sort_keys=True)


@pytest.fixture(scope='module')
def server():
    import flask

    app = flask.Flask(__name__)
    app.config.update(
        OIDC_CLIENT_SECRETS=oidcat.util.with_well_known_secrets_file(
            HOST, CLIENT_ID, CLIENT_SECRET),
        PROPAGATE_EXCEPTIONS=True,
        SECRET_KEY='blagh')

    oidc = oidcat.server.OpenIDConnect(app, '/tmp/creds.db')

    @app.route('/')
    def index():
        return flask.jsonify({'success': True})

    @app.route('/special')
    @oidc.accept_token(role=TEST_ROLE)
    def special():
        token = oidc.valid_token()
        assert token.preferred_username == USERNAME
        assert token.check_roles(TEST_ROLE, TEST_MISSING_ROLE) == [True, False]
        return flask.jsonify({'success': True})

    @app.route('/inaccessible')
    @oidc.accept_token(role=TEST_MISSING_ROLE)
    def inaccessible():
        return flask.jsonify({'success': True})

    @app.route('/accessible')
    def accessible():
        token = oidc.valid_token(required=True)
        r1, r2 = token.check_roles(TEST_ROLE, TEST_MISSING_ROLE, required=True)
        assert r1 and not r2
        return flask.jsonify({'success': True})

    @app.route('/inaccessible2')
    def inaccessible2():
        token = oidc.valid_token()
        token.check_roles(TEST_MISSING_ROLE, required=True)
        return flask.jsonify({'success': True})

    @app.errorhandler(Exception)
    def err_handle(e):
        return oidcat.exc2response(e, asresponse=True)

    with app.test_client() as client:
        yield client
        # with app.app_context():
        #     yield client

# @pytest.fixture
# def client(client):


@pytest.fixture(scope="module")
def sess():
    yield oidcat.Session(HOST, USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET)

@pytest.fixture
def bearer(sess):
    # print(sess)
    print(dump(dict(sess.access.well_known)))
    print(dump(dict(sess.access.token)))
    print(sess.access.well_known.client_id, type(sess.access.well_known.client_secret))
    yield {'Authorization': 'Bearer {}'.format(sess.access.token)}


def test_core(server):
    assert getitem2(server.get('/').get_json(), 'success') is True

def test_protected(server, bearer):
    print(bearer)
    assert server.get('/special').status_code == 401
    assert getitem2(server.get('/special', headers=bearer).get_json(), 'success') is True

def test_inaccessible(server, sess, bearer):
    assert server.get('/inaccessible').status_code == 401
    assert server.get('/inaccessible', headers=bearer).status_code == 401

def test_accessible(server, sess, bearer):
    print('accessible 1')
    assert server.get('/accessible').status_code == 401
    print('accessible 2')
    assert getitem2(server.get('/accessible', headers=bearer).get_json(), 'success') is True

def test_inaccessible2(server, sess, bearer):
    assert server.get('/inaccessible').status_code == 401
    assert server.get('/inaccessible', headers=bearer).status_code == 401
