import json
import base64
import datetime
from . import util
from .exceptions import *

__all__ = ['Token']


class Token(dict):
    _FOREVER_ = datetime.timedelta(seconds=3600*24*5000)
    def __init__(self, token='', buffer=None, valid=True):
        self.token = token or None
        self.header, data, self.signature = Token.decode(token) if token else ({}, {}, '')
        super().__init__(data)

        expires = self.get('exp')
        self.expires = datetime.datetime.fromtimestamp(expires) if expires else None
        if buffer is None and self.expires:
            buffer = min(max((self.expires - datetime.datetime.now()).total_seconds() * 0.05, 0), 30)
        self.buffer = (
            buffer if isinstance(buffer, datetime.timedelta) else
            datetime.timedelta(seconds=buffer or 0))
        self._valid = valid

    def __repr__(self):
        return 'Token({})'.format(super().__repr__())

    def __str__(self):
        return str(self.token)

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError as e:
            raise KeyError('{} not found in: {}'.format(str(e), set(self)))

    def __getattr__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError as e:
            raise AttributeError('{} not found in: {}'.format(str(e), set(self)))

    def __bool__(self):
        return bool(self.token) and (not self.expires or self.time_left > self.buffer)

    @property
    def time_left(self):
        return self.expires - datetime.datetime.now() if self.expires else self._FOREVER_

    @property
    def valid(self):
        return self.token and self._valid is True and (not self.expires or self.time_left.total_seconds() > 0)

    @valid.setter
    def valid(self, value):
        self._valid = value

    @property
    def username(self):
        return self.preferred_username

    @staticmethod
    def decode(token):
        header, data, signature = token.split('.')
        return partdecode(header), partdecode(data), signature

    @staticmethod
    def encode(header, data, signature=None):
        header, data = partencode(header), partencode(data)
        signature = signature or hash(str(header+data))  # default to dummy signature
        return '.'.join((header, data, signature))

    @classmethod
    def astoken(cls, token, *a, **kw):
        return token if isinstance(token, cls) else cls(token, *a, **kw)

    def get_roles(self, client_id=False, mode='keycloak'):
        # get roles from token
        realm_roles, client_roles = [], []
        if mode in ('keycloak', 'kc'):
            if 'realm_access' in self:
                realm_roles = self['realm_access']['roles']
            if client_id is True:
                client_id = list(self.get('resource_access') or ())
            for c in util.aslist(client_id):
                try:
                    client_roles.extend(r for r in self['resource_access'][c]['roles'])
                except KeyError:
                    pass
        else:
            raise ValueError('Unknown token schema: {!r}'.format(mode))
        return realm_roles + client_roles, realm_roles, client_roles

    def has_role(self, *roles, realm=None, client=None, client_id=True, mode='keycloak'):
        available = self.get_roles(client_id=client_id, mode=mode)
        return all(
            (not req or any(r in avail for r in util.aslist(req)))
            for req, avail in zip((roles, realm, client), available))

    def check_roles(self, *roles, realm_only=None, client_only=None, client_id=True, mode='keycloak', required=False):
        all_roles, realm_roles, client_roles = self.get_roles(client_id=client_id, mode=mode)
        if realm_only:
            has_roles = [r in realm_roles for r in roles]
        elif client_only:
            has_roles = [r in client_roles for r in roles]
        else:
            has_roles = [r in all_roles for r in roles]

        if required:  # make sure we have at least one
            required = any if required is True else required
            if not required(has_roles):
                raise Unauthorized()
        return has_roles

def partdecode(x):
    return json.loads(base64.b64decode(x + '===').decode('utf-8'))

def partencode(x):
    return base64.b64encode(json.dumps(x).encode('utf-8')).decode('utf-8')


def mod_token(token, **kw):
    header, data, sig = Token.decode(token)
    data.update(**kw)
    return Token.encode(header, data, sig)



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
