'''Comprehensive token management.

Token validation requires looking at several different things, but at the end of the day, really I just wanna know, "can I use this? or do I need to go grab a new one?"

Token objects encapsulate the different forms of a token: a string, a data payload, a valid or invalid key.

.. code-block:: python

    # assuming we are logged in using a Session object...
    token = sess.access.token
    refresh_token = sess.access.refresh_token

    # works as a boolean
    if token:
        # works as a dict (by dict key or by attribute)
        print("My name:", token.given_name, "and my username:", token['preferred_username'])
        
        # you can see what's inside of it
        print(repr(token))  # shows the data payload and validity as a formatted string
        print(dict(token))  # gets the data payload as a dict

        # works as a string (e.g. str(token))
        headers = {'Authorization': 'Bearer {}'.format(token)}
    else:
        print('R.I.P. this token is dead')
'''
import json
import base64
import datetime
from . import util
from .exceptions import *

__all__ = ['Token']

class _MODES:
    KEYCLOAK = ('keycloak', 'kc', None)
    VALID = KEYCLOAK  # + SOMETHINGELSE
    @classmethod
    def unknown(self, mode):
        raise ValueError('Unknown token schema: {!r}'.format(mode))

class Token(dict):
    '''Represents a token as both a string and as a data payload.
    
    .. code-block:: python

        token_str = 'iobequfebqi...'
        token = Token(token_str)

        # access as a string
        assert token.token == token_str
        assert str(token) == token_str

        # access keys from the token
        assert token.preferred_username == 'your-username'
        assert token.given_name == 'Your Name'
        assert token.iat == 12345
        assert token['iat'] == 12345  # same deal

        # Check token validity
        assert token, "This token is either missing, invalid, or expired."
        print('Ah well if that worked, I guess our token is valid then!')

        # Check if the token contains certain roles

    Arguments:
        token (str): The token string.
        buffer (float): The minimum time left to consider a token valid. This helps prevent the case 
            where the token was valid before you sent your request, but by the time you sent your request
            it became invalid. Typically you want this set above the amount of time it would take to 
            complete a slower request.
        valid (bool): A flag that can be used to override token validity. (Can be set after checking the auth server blacklist for example).
        format (str): The token role format. Currently only supports 'keycloak'.
    '''
    _FOREVER_ = datetime.timedelta(seconds=3600*24*5000)
    def __init__(self, token='', buffer=None, valid=True, format='keycloak'):
        self.token = token or None
        self.header, self.data, self.signature = jwt_decode(token) if token else ({}, {}, '')
        super().__init__(self.data)

        expires = self.get('exp')
        self.expires = datetime.datetime.fromtimestamp(expires) if expires else None
        if buffer is None and self.expires:
            buffer = min(max((self.expires - datetime.datetime.now()).total_seconds() * 0.05, 0), 30)
        self.buffer = (
            buffer if isinstance(buffer, datetime.timedelta) else
            datetime.timedelta(seconds=buffer or 0))
        self._valid = valid

        # check token format
        if format not in _MODES.VALID:
            _MODES.unknown(format)
        self._format = format

    def __repr__(self):
        '''Show the token information, including expiration and data payload.'''
        if self.token is None:
            return 'Token(None)'
        return 'Token(time_left={}, {})'.format(self.time_left, super().__repr__())

    def __str__(self):
        '''Get the token as a string (can be passed in an Authorization header)'''
        return str(self.token or '')

    def __getitem__(self, key):
        '''Retrieve an item from the token payload.'''
        try:
            return super().__getitem__(key)
        except KeyError as e:
            raise KeyError('{} not found in: {}'.format(str(e), set(self)))

    def __getattr__(self, key):
        '''Retrieve an item from the token payload.'''
        try:
            return super().__getitem__(key)
        except KeyError as e:
            raise AttributeError('{} not found in: {}'.format(str(e), set(self)))

    def __bool__(self):
        '''Check if the token exists and is not expired.'''
        return bool(self.token) and (not self.expires or self.time_left > self.buffer)

    @property
    def time_left(self):
        '''Get how much time left is in the token.'''
        return (
            self.expires - datetime.datetime.now() if self.expires else 
            self._FOREVER_ if self.token else 
            datetime.timedelta(seconds=0))

    @property
    def valid(self):
        '''Determines if the token is valid and is not expired.'''
        return self.token and self._valid is True and (not self.expires or self.time_left.total_seconds() > 0)

    @valid.setter
    def valid(self, value):
        self._valid = value

    @property
    def validity(self):
        '''Returns True if the token is valid or a string describing the reason that the token is invalid.'''
        return (
            'No token' if not self.token else
            'Token invalid' if not self._valid else
            'Token expired' if (self.expires and self.time_left.total_seconds() <= 0)
            else True)

    @property
    def username(self):
        '''An alias for the username of the token owner.'''
        return self.preferred_username

    @property
    def roles(self):
        '''Get all realm and client roles.'''
        return self.realm_roles | self.client_roles()

    @property
    def realm_roles(self):
        '''Get all realm roles in the token.'''
        if self._format in _MODES.KEYCLOAK:
            return set((self.get('realm_access') or {}).get('roles') or ())
        return set()

    def client_roles(self, client_id=None, *additional, allow_missing=True):
        '''Get all client roles in the token.
        
        Arguments:
            client_id (list, str): The client ID(s) to include. If not specified, it will get the roles from all clients in the token.

        Returns:
            roles (list): The list of matching client roles.
        '''
        if self._format in _MODES.KEYCLOAK:
            rsc = self.get('resource_access') or {}
            all_clients = list(rsc)
            if client_id is None or client_id is True:
                client_id = all_clients
            client_id = util.aslist(client_id) + list(additional)

            missing_clients = set(client_id) - set(all_clients)
            if missing_clients:
                if not allow_missing:
                    raise ValueError('clients {} not in available clients {}.'.format(missing_clients, all_clients))
            return set(
                r for c in client_id
                for r in (rsc.get(c) or {}).get('roles') or ())
        return set()

    @classmethod
    def astoken(cls, token, *a, **kw):
        '''Given a Token object or a string or None, convert it to a Token object.
        
        Arguments:
            token (Token, str, None): the token.
            *a: Additional arguments to pass to ``Token(...)`` if token is undefined.
            **kw: Additional keyword arguments to pass to ``Token(...)`` if token is undefined.

        Returns:
            token (Token): the token coerced to a Token object.
        '''
        return token if isinstance(token, cls) else cls(token, *a, **kw)

    def has_role(self, *roles, realm=None, client=None, client_id=True, **kw):
        '''Check if the token has certain roles.

        Arguments:
            *roles (str): the roles to look for.
            realm (str, list, None): the realm roles to look for.
            client (str, list, None): the client roles to look for.
            client_id (str, bool): the client ID(s) to check against. By default, it looks at all clients.
            required (bool, callable): Should we throw an error for missing roles? (default is False).
                If callable (e.g. ``all`` or ``any``), the function will receive a list of booleans representing if the token has the role.
                If True, then it will use ``any``.

        Returns:
            has_roles (bool): Whether or not the user has any of the roles.
        '''
        realm_roles = self.realm_roles if realm is not False else set()
        client_roles = self.client_roles(client_id) if client_id else set()
        return all(
            (not req or any(compare_roles(req, avail, asdict=False, **kw)))
            for req, avail in zip((roles, realm, client), (realm_roles | client_roles, realm_roles, client_roles)))

    def check_roles(self, *roles, realm_only=None, client_only=None, client_id=True,
                    asdict=False, required=False):
        realm_roles = self.realm_roles if not client_only else set()
        client_roles = self.client_roles(client_id) if not realm_only else set()
        target_roles = realm_roles if realm_only else client_roles if client_only else (realm_roles | client_roles)
        return compare_roles(roles, target_roles, asdict=asdict, required=required)



def compare_roles(targets, existing, required=False, asdict=False):
    '''Compare target roles with a set of existing roles.

    Arguments:
        *roles (str): the roles to look for.
        realm (str, list, None): the realm roles to look for.
        client (str, list, None): the client roles to look for.
        client_id (str, bool): the client ID(s) to check against. By default, it looks at all clients.
        required (bool, callable): Should we throw an error for missing roles? (default is False).
            If callable (e.g. ``all`` or ``any``), the function will receive a list of booleans representing if the token has the role.
            If True, then it will use ``any``.

    Returns:
        has_roles (bool): Whether or not the user has any of the roles.
    '''
    targets, existing = util.aslist(targets), util.as_set(existing)
    has_roles = {r: r in existing for r in targets}

    if required:  # make sure we have at least one
        required = any if required is True else required
        if not required(has_roles.values()):
            raise Unauthorized('Insufficient privileges. unable to: {}'.format(
                [role for role, has in has_roles.items() if not has]))
    return has_roles if asdict else [has_roles[r] for r in targets]


def partdecode(x):
    '''Decode the token base64 string part as a dictionary. Split the token using ``'.'`` first.'''
    return json.loads(base64.b64decode(x + '===').decode('utf-8'))

def partencode(x):
    '''Encode the token dictionary payload as a base64 string.'''
    return base64.b64encode(json.dumps(x).encode('utf-8')).decode('utf-8')


def jwt_decode(token):
    '''Decode a token into it's parts and parse the json payloads.
    
    Arguments:
        token (str): the token string

    Returns:
        header (dict): the header payload.
        data (dict): the data payload.
        signature (str): the token signature.
    '''
    header, data, signature = token.split('.')
    return partdecode(header), partdecode(data), signature


def jwt_encode(header, data, signature=None):
    '''Take a token's parts and convert it to a token. This is only really used for mocking a token for testing purposes.
    
    Arguments:
        header (dict): the header payload.
        data (dict): the data payload.
        signature (str): the token signature.

    Returns:
        token (str): the token string
    '''
    header, data = partencode(header), partencode(data)
    signature = signature or hash(str(header+data))  # default to dummy signature
    return '.'.join((header, data, signature))



def mod_token(token, **kw):
    '''Modify the token data payload.
    
    .. warning::
        This will invalidate the token. It is meant for testing purposes.

    Arguments:
        token (str): the token string.

    Returns:
        token (str): the (invalidated) modified token string.
    '''
    header, data, sig = jwt_decode(token)
    data.update(**kw)
    return jwt_encode(header, data, sig)
