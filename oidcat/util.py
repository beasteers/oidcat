import os
import urllib
from . import RequestError
from .exceptions import safe_format
from .env import Env



def _asitems(itemtype, *othertypes):
    '''A helper meta function that generates casting functions. 
    e.g.: ``aslist = _asitems(list, tuple, set)``'''
    def inner(x, split=None):
        if split and isinstance(x, str):
            x = x.split(split)
        return (
            x if isinstance(x, itemtype) else
            itemtype(x) if isinstance(x, othertypes) else
            [x] if x is not None and x != '' else [])
    name = itemtype.__name__
    inner.__name__ = funcname = 'as{}'.format(name)
    inner.__doc__ = '''Convert value to {name}.

    ``None`` becomes an empty {name}.
    Other types ({others}) are cast to {name}.
    Everything else becomes a single element {name}.
    If you want all Falsey values to convert to an empty list,
    then do ``{func}(value or None)``
    '''.format(
        name='``{}``'.format(name), 
        others=', '.join('``{}``'.format(c.__name__) for c in othertypes),
        func=funcname)
    return inner


aslist = _asitems(list, tuple, set)
as_set = _asitems(set, tuple, list)
astuple = _asitems(tuple, list, set)

def asfirst(x):
    '''Get the first value in a list. Also handle's single values or empty values.
    For empty values, None is returned.'''
    return (x[0] if isinstance(x, (list, tuple)) else x) if x else None


def asurl(url, *paths, secure=None, **args):
    '''Given a hostname, convert it to a URL.

    .. code-block:: python

        # schema
        assert oidcat.util.asurl('my.server.com') == 'https://my.server.com'
        assert oidcat.util.asurl('localhost:8080') == 'http://localhost:8080'
        assert oidcat.util.asurl('my.server.com', secure=False) == 'http://my.server.com'

        # adding paths
        assert oidcat.util.asurl('my.server.com', 'something', 'blah') == 'https://my.server.com/something/blah'

        # argument formatting
        assert oidcat.util.asurl('my.server.com', myvar=1, othervar=2) == 'https://my.server.com?myvar=1&othervar=2'
        assert oidcat.util.asurl('my.server.com?existingvar=0#helloimahash', myvar=1, othervar=2) == 'https://my.server.com?existingvar=0&myvar=1&othervar=2#helloimahash'

    Arguments:
        url (str): The hostname. Can start with https?:// or can just be my.domain.com.
        *paths (str): The paths to append to the URL.
        secure (bool): Should we use http or https? If not specified, it will use https (unless it's localhost)
            If it already starts with https?://, then this is ignored.
        **args: query parameters to add to the url.
    '''
    if url:
        if not (url.startswith('http://') or url.startswith('https://')):
            if secure is None:
                secure = not url.startswith('localhost')
            url = 'http{}://{}'.format(bool(secure)*'s', url)
        url = os.path.join(url, *(p.lstrip('/') for p in paths if p))
        # add args, and make sure they go before the hashstring
        args = {k: v for k, v in args.items() if v is not None}
        if args:
            url, hsh = url.split('#', 1) if '#' in url else (url, '')
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(args)
            if hsh:
                url += '#' + hsh
        return url


def as_realm_url(url, *path, realm=None, base=None, secure=None):
    return asurl(url, (base or '').strip('/'), 'realms', realm or 'master', *path, secure=secure)


class Role(list):
    '''Define a set of roles: e.g.

    .. code-block:: python

        r, w, d = Role('read'), Role('write'), Role('delete')
        r.audio + r.any.spl + (r+w).meta + d('audio', 'spl')
        # ['read-audio', 'read-any-spl', 'read-any-meta', 'write-any-meta',
        #  'delete-audio', 'delete-spl']
    '''
    def __init__(self, *xs):
        super().__init__(
            xi for x in xs for xi in (
                [x] if isinstance(x, str) else x))

    def __call__(self, *keys):
        return Role('{}-{}'.format(i, ki) for i in self for k in keys for ki in Role(k))

    def __add__(self, *xs):
        return Role(self, *Role(*xs))

    def __getattr__(self, k):
        return self(k)

    def __radd__(self, x):
        # return Role(x).join(self)  # << idk wtf that was supposed to be
        return Role(x) + self
