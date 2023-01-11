import os


class Env:
    '''Get environment variables. Makes for easy variable namespacing/prefixing.'''
    def __init__(self, prefix=None, upper=True, **kw):
        self.prefix = prefix or ''
        self.upper = upper
        self.vars = kw
        if self.upper:
            self.prefix = self.prefix.upper()

    def __str__(self):
        '''Show the matching environment variables.'''
        return '<env {}>'.format(''.join([
            '\n  {}={}'.format(k, self(k)) for k in self.vars
        ]))

    def __contains__(self, key):
        '''Does that key (plus prefix) exist?'''
        return self.key(key) in os.environ

    def __getattr__(self, key):
        '''Get the environment variable.'''
        return self.get(key)

    def __call__(self, key, default=None, *a, **kw):
        return self.get(key, default, *a, **kw)

    def get(self, key, default=None, cast=None):
        '''Get the environment variable.'''
        y = os.environ.get(self.key(key))
        if y is None:
            return default
        if callable(cast):
            return y
        if y in ('1', '0'):
            y = int(y)
        if y.lower() in ('y', 'n'):
            y = y.lower() == 'y'
        return y

    def gather(self, *keys, **kw):
        '''Get multiple environment variables. You can do it either

        Arguments:
            *keys: the keys to get.
            **kw: if ``*keys`` is empty, these keys to get, also allowing you to rename the keys in the return value. 
                The values will be used to lookup and the keys will be used to rename the variable.
                If ``*keys`` is not empty, ``**kw`` will be passed to ``self.get`` instead.

        Returns:
            values (str, list, dict): if ``len(keys) == 1``, then it will return a single value.
                Otherwise it will return a list. If ``*keys`` are not specified and ``**kw`` is, 
                it will return a dictionary.

        .. code-block:: python

            env = Env('app_')  # we're trying to access: APP_HOST, APP_USERNAME
            assert env.gather('host') == 'myhost.com'
            assert env.gather('host', 'username') == ['myhost.com', 'myusername']
            assert env.gather(url='host', user='username') == {'url': 'myhost.com', 'user': 'myusername'}
        '''
        return (
            (self.get(keys[0], **kw) if len(keys) == 1 else [self.get(k, **kw) for k in keys])
            if keys else {k: self.get(v) for k, v in kw.items()}
        )

    def key(self, x):
        '''Prepare the environment key.'''
        k = (self.prefix or '') + self.vars.get(x, x)
        return k.upper() if self.upper else k

    def all(self):
        '''Get all environment variables that match the prefix.'''
        return {k: v for k, v in os.environ.items() if k.startswith(self.prefix)}

    DELETE = object()

    def set(self, **kw):
        for k, v in kw.items():
            k = self.key(k)
            if v is self.DELETE:
                del os.environ[k]
                continue
            os.environ[k] = str(v)

