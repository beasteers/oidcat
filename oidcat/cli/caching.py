import os
import json
import contextlib


@contextlib.contextmanager
def saveddict(fname):
    '''A context manager that lets you store data in a JSON file. This is useful for storing configuration values 
    between runs (great for configuring CLIs).
    If ``fname`` is None, then nothing is saved to file.

    .. code-block:: python

        # you can use either
        fname = None  # this just won't save anything
        fname = 'my/params-file.json'

        with oidcat.util.saveddict(fname) as cfg:
            cfg['host'] = host or cfg.get('host') or SOME_DEFAULT_HOST
            cfg['username'] = (
                username or cfg.get('username') or
                oidcat.util.ask("what's your username?"))
            password = (
                password or cfg.get('password') or
                oidcat.util.ask("what's your password?", secret=True))
            if store_password:  # not very secure !!
                cfg['password'] = password

    '''
    import base64
    try:
        data = {}
        fname = fname and os.path.expanduser(fname)
        if fname and os.path.isfile(fname):
            try:
                with open(fname, 'rb') as f:
                    data = json.loads(base64.b64decode(f.read()).decode('utf-8'))
            except json.decoder.JSONDecodeError:
                pass
        yield data
    finally:
        if fname:
            os.makedirs(os.path.dirname(fname) or '.', exist_ok=True)
            with open(fname, 'wb') as f:
                f.write(base64.b64encode(json.dumps(data).encode('utf-8')))
