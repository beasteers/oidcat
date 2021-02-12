import os
import pytest

import oidcat.server


HOST = os.getenv('KEYCLOAK_HOST') or 'localhost'
CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID') or 'admin-cli'
CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET') or None
TEST_ROLE = os.getenv('KEYCLOAK_ROLE') or 'editor'
TEST_MISSING_ROLE = 'asdfaoinsadfn'
USERNAME = os.getenv('KEYCLOAK_USER') or 'admin'
PASSWORD = os.getenv('KEYCLOAK_PASS') or 'admin'

@pytest.fixture(scope='module')
def server():
    import flask

    app = flask.Flask(__name__)
    app.config.update(
        OIDC_CLIENT_SECRETS=oidcat.util.with_well_known_secrets_file(
            HOST, CLIENT_ID, CLIENT_SECRET),
        SECRET_KEY='blagh')

    oidc = oidc = oidcat.server.OpenIDConnect(app, '/tmp/creds.db')

    @app.route('/')
    def index():
        return flask.jsonify({'success': True})

    @app.route('/special')
    @oidc.accept_token(keycloak_role=TEST_ROLE)
    def special():
        return flask.jsonify({'success': True})

    @app.route('/inaccessible')
    @oidc.accept_token(keycloak_role=TEST_MISSING_ROLE)
    def inaccessible():
        return flask.jsonify({'success': True})

    with app.test_client() as client:
        with app.app_context():
            yield client

@pytest.fixture
def authheaders():
    sess = oidcat.Session(HOST, USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET)
    yield {'Authorization': 'Bearer {}'.format(sess.access_token)}


def test_core(server):
    assert server.get('/').get_json()['success'] is True

def test_protected(server, authheaders):
    assert server.get('/special').status_code == 401
    assert server.get('/special', headers=authheaders).get_json()['success'] is True



def test_inaccessible(server, authheaders):
    assert server.get('/inaccessible').status_code == 401
    sess = oidcat.Session(HOST, USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET)
    assert server.get('/inaccessible', headers=authheaders).status_code == 401
