'''Server-Side Components for Protecting Resources via a Flask app.

Connecting to Flask App
-----------------------

.. code-block:: python

    import flask
    import oidcat.server

    app = Flask(__name__)
    oidc = oidcat.server.OIDC(app)


Protecting Routes Using Roles
-----------------------------

As of right now, there are several different ways of protecting a route
based on a user's access level. I'm still trying to figure out the best way.

Current Recommended Way
=======================
This offers the most flexibility because you can define the token checking however
you want.

But the problem is that you won't know if a user has permission to access the data
until you run the view function (because it is totally coupled to the data handling).

.. code-block:: python

    @app.route('/<dataid>')
    def data(dataid):
        # gets the token and makes sure it is still valid and not expired/revoked.
        token = oidc.valid_token(required=True)
        # check if the token has any of these roles.
        # it returns a boolean corresponding to the presence of each role in the
        # token, in the same order as provided. Because `required=True`, if the
        # token has neither of these roles, it will raise an oidcat.Unauthorized error.
        r_any, r_mine = token.check_roles('read-all-data', 'read-my-data', required=True)
        assert r_any or r_mine  # one of these will always be true

        # r_any here is used basically as admin access for developers where you
        # can access any data
        # r_mine means that you have access to data associated with your data ids

        # if the user doesn't have admin access, then check if they have access to
        # that data if it's in their token attributes
        if not r_any or dataid not in token.my_data_ids:
            raise oidcat.Unauthorized(
                "You don't have access to this specific piece of data.")

        # now we know that the user has the proper access, give them the data!
        return flask.jsonify({'success': True, 'data': [1, 2, 3]})

Upcoming Way
============

This is a newly developed so its API is still in flux and likely to
change (consider it Alpha stage).

The benefit that this has is that it decouples the token checking from the
data handling meaning that we're one step closer to static analysis of route
permissions!

.. code-block:: python

    # define the permissions function

    @oidc.server.protection
    def check_roles(resource):
        token = oidc.valid_token(required=True)
        can_read = token.check_roles('read-'+resource, required=True)
        # the return format is arbitrary and the value will be
        # passed to `permissions` if it's value is not None.
        return token, can_read

    # wrap the view function with the permissions checker

    @app.route('/<dataid>')
    @check_roles('data')
    def data(dataid, permissions):
        return flask.jsonify({'success': True, 'data': [1, 2, 3]})

    # now here's a simple way to check if a certain user has
    # permissions for a certain route.

    @app.route('/<dataid>/check_if_i_have_access')
    def data_permissions_check(dataid):
        return flask.jsonify({'has_access': data.protection.has_permissions()})

'''
import os
import json
import functools
import flask
from flask import request, current_app, g
import flask_oidc
import oidcat
from .. import util, Unauthorized, RequestError, exc2response
from ..token import Token

log = flask_oidc.logger


class OpenIDConnect(flask_oidc.OpenIDConnect):
    @functools.wraps(flask_oidc.OpenIDConnect.__init__)
    def __init__(self, app=None, credentials_store=None, *a, **kw):
        if isinstance(credentials_store, str):
            import sqlitedict
            credentials_store = sqlitedict.SqliteDict(
                credentials_store, autocommit=True)
        super().__init__(app, credentials_store, *a, **kw)


    def init_app(self, app):
        super().init_app(app)
        app.config.setdefault('OIDC_OAUTH2_PROVIDER', 'keycloak')
        app.errorhandler(RequestError)(exc2response)

    def _validate_token(self, token, scopes_required=None):
        '''Make sure the token is considered valid by the auth server and that it has the
        required scopes/audience.'''
        # NOTE: refactored from flask_oidc to make the logic clearer and error messages more helpful
        if not token:
            return 'Missing token'

        # try to introspect the token
        try:
            token_info = self._get_token_info(token)
            if 'error' in token_info:
                return 'Error received when querying token info: {}'.format(token_info)
        except Exception as e:
            return 'Error while trying to query token info: {}'.format(e)

        # see if the token is considered active
        valid_token = token_info.get('active', False)
        if not valid_token:
            return 'Token is not active.'

        # validate the token audience
        if 'aud' in token_info and current_app.config['OIDC_RESOURCE_CHECK_AUD']:
            valid_audience = self.client_secrets['client_id'] in util.aslist(token_info['aud'])
            if not valid_audience:
                # log.error('Refused token because of invalid audience')
                return 'Refused token because of invalid audience'

        # check that it has the required scopes
        scopes_required = set(util.aslist(scopes_required))
        token_scopes = set(token_info.get('scope', '').split(' ')) if valid_token else set()
        has_required_scopes = scopes_required.issubset(token_scopes)
        if not has_required_scopes:
            return 'Token does not have required scopes'

        # if everything is good, store the token info
        g.oidc_token_info = token_info
        return True

    def accept_token(self, scopes=None, role=None, realm_role=None, client_role=None,
                     required=True, checks=None):
        def wrapper(view_func):
            @functools.wraps(view_func)
            def decorated(*a, **kw):
                self.valid_token(*util.aslist(role), scopes=scopes,
                                 realm_role=realm_role, client_role=client_role,
                                 required=required, checks=checks)
                return view_func(*a, **kw)
            return decorated
        return wrapper

    # get token

    @property
    def token(self):
        '''Get the current token object.

        Returns:
            token (Token): the token object. May be empty (token.token is None).
        '''
        token = getattr(flask.g, 'oidc_token_obj', None)
        if token is None:
            token = (
                self._get_bearer_token() or
                request.form.get('access_token') or
                request.args.get('access_token') or
                self.get_access_token() or None)
            if token:
                token = Token(token)
            flask.g.oidc_token_obj = token
        token = token if token is not None else Token()
        token._format = flask.current_app.config['OIDC_OAUTH2_PROVIDER']
        return token

    def valid_token(self, *roles, scopes=None, realm_role=None, client_role=None,
                    client_id=True, required=True, checks=None, token=None):
        '''Check if a token is valid.

        Arguments:
            *roles (str): roles to check.
            scopes (list, str, None): scopes to check for.
            realm_role (list, str, None): realm roles to check for.
            client_role (list, str, None): client roles to check for.
            client_id (list, str, None): the client ID(s) to check. By default, will
                check the current client.
            required (bool, callable): Are the roles required? If True, then the token
                should have at least one role. To require all roles, do ``require=all``.
            checks (list[callable]): a list of additional checks to do on the token.
                Receives the Token object as the only argument.
            token (Token, str, None): Gives you the option to pass your own external token.

        Returns:
            token (Token): The token object. If invalid, bool(token) will evaluate to False.

        Raises:
            oidcat.UnauthorizedError if required is True and the token is invalid.
        '''
        # check if token is valid
        token = self.token if token is None else Token.astoken(token)
        token._format = flask.current_app.config['OIDC_OAUTH2_PROVIDER']
        validity = token.validity

        if validity is True and not token.token:
            validity = 'No token'  # redundant
        if validity is True:
            validity = self.validate_token(token.token, scopes)
        if validity is True:
            # make sure it has one of the required roles, and that all arbitrary checks pass.
            try:
                validity = self.has_role(
                    *roles, realm=realm_role, client=client_role, client_id=client_id,
                    required=True)
            except oidcat.Unauthorized as e:
                validity = str(e)
            if validity is True and not all(chk(token) for chk in checks or ()):
                validity = 'Insufficient privileges.'
        token.valid = True if validity is True else Unauthorized(str(validity))

        # on no! I'm not supposed to talk to strangers!
        if required and validity is not True:
            raise Unauthorized(str(validity))
        return token

    def get_access_token(self):
        return super().get_access_token() if flask.g.oidc_id_token else None

    def _get_bearer_token(self):
        auth = request.headers.get('Authorization') or ''
        return auth.split(None,1)[1].strip() if auth.startswith('Bearer ') else None

    # check token

    def has_role(self, *roles, realm=None, client=None, client_id=True, **kw):
        if client_id is True:
            client_id = self.client_secrets['client_id']
        return self.token.has_role(*roles, realm=realm, client=client, client_id=client_id, **kw)

    def require_role(self, *roles, **kw):
        return self.require(self.has_role(*roles, **kw))

    def require(self, test, msg=None):
        if not test:
            raise Unauthorized(msg)


    def load_secrets(self, app):  # this is from master, but is not available in the current pip package
        # Load client_secrets.json to pre-initialize some configuration
        return _json_loads(app.config['OIDC_CLIENT_SECRETS'])

    def protection(self, permission):
        return _Protection.define(permission)

    def protect_roles(self, *roles):
        return _Protection.define(_oneof_role_protection)(self, *roles)


def _oneof_role_protection(oidc, *roles):
    token = oidc.valid_token()
    return token, token.check_roles(*roles, required=True)

# https://github.com/googleapis/oauth2client/blob/0d1c814779c21503307b2f255dabcf24b2a107ac/oauth2client/clientsecrets.py#L119
def _json_loads(content):
    if isinstance(content, dict):
        return content
    if os.path.isfile(content):
        with open(content, 'r') as f:
            content = f.read()
    if not isinstance(content, str):
        content = content.decode('utf-8')
    return json.loads(content)


class _Protection:
    '''

    .. code-block python

        @oidcat.server.protection
        def check_roles(resource):
            token = oidc.valid_token()
            r = oidcat.role.read
            rany, rmine, rbasic = token.check_roles(*(r+r.any)(resource), required=True)
            if not rany and deployment_id not in token.deployment_id:
                raise oidcat.Unauthorized()
            return token, rany, rmine, rbasic

        @app.route('/secret/<key>')
        @check_roles('data')
        def secret(key, permissions):
            token, rany, rmine, rbasic = permissions
            return mysecretdata(key)

    '''
    def __init__(self, permission, *a, _view_func=None, permissions_key='permissions', **kw):
        self.permission = permission
        self.func = _view_func
        self.key = permissions_key
        self.a = a
        self.kw = kw
        functools.update_wrapper(self, permission)

    def __call__(self, *a, **kw):
        permissions = self.require_permissions(*a, **kw)
        if self.func is not None:
            if permissions is not None and self.key:
                kw[self.key] = permissions
            return self.func(*a, **kw)
        return permissions

    def has_permissions(self, *a, **kw):
        try:
            self.require_permissions(*a, **kw)
            return True
        except oidcat.Unauthorized:
            return False

    def require_permissions(self, *a, **kw):
        return self.permission(*self.a, *a, **self.kw, **kw)

    @classmethod
    def define(cls, permission):  # wraps the permissions check
        def wrap_args(*a, **kw):  # wraps arguments for the permissions check
            def wrap_func(func):  # wraps view func with permissions check
                protected = cls(permission, *a, _view_func=func, **kw)

                @functools.wraps(func)
                def view(*a, **kw):
                    return protected(*a, **kw)
                view.protection = protected
                return view
            return wrap_func
        return wrap_args


protection = _Protection.define


# def _g_get_once(key, default=None):
#     try:
#         return getattr(g, key)
#     except AttributeError:
#         setattr(g, key, default() if callable(default) else default)

# def request_cached(func, *a, **kw):  # TODO: I want to cache OIDC.validate_token
#     cache = _g_get_once('oidcat_cache', dict)
#     key = '{}{}{}'.format(func.__name__, str(a), str(kw))
#     try:
#         return cache[key]
#     except KeyError:
#         val = cache[key] = func(*a, **kw)
#         return val



OIDC = OpenIDConnect
