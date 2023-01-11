import functools

class Colors(dict):
    '''Color text. e.g.

    To use the builtin colors:

    .. code-block:: python

        print(oidcat.util.color('hi', 'red') + oidcat.util.color.blue('hello') + oidcat.util.color['green']('sup'))
    '''
    def __call__(self, x, name=None):
        if not name:
            return str(x)
        return '\033[{}m{}\033[0m'.format(super().__getitem__(name.lower()), x) if name else x

    def __getitem__(self, k):
        if k not in self:
            raise KeyError(k)
        return functools.partial(self.__call__, name=k)

    def __getattr__(self, k):
        if k not in self:
            raise AttributeError(k)
        return functools.partial(self.__call__, name=k)


color = Colors(
    black='0;30',
    red='0;31',
    green='0;32',
    orange='0;33',
    blue='0;34',
    purple='0;35',
    cyan='0;36',
    lightgray='0;37',
    darkgray='1;30',
    lightred='1;31',
    lightgreen='1;32',
    yellow='1;33',
    lightblue='1;34',
    lightpurple='1;35',
    lightcyan='1;36',
    white='1;37',
)
Colors.__doc__ = '''{}

Builtin colors:
{}
'''.format(
    Colors.__doc__ or "",
    '\n'.join(
    ' - ``{}``: ``{}``'.format(k, v)
    for k, v in color.items()
))

color_ = color


def ask(question, color=None, secret=False):
    '''Prompt the user for input.

    .. code-block:: python

        oidcat.util.ask("what's your username?", 'purple')
        oidcat.util.ask("what's your password?", 'purple', secure=True)

    Arguments:
        question (str): the prompt message.
        color (str, None): the color name for the prompt message.
            See ``oidcat.util.color`` for available colors.
        secret (bool): Is the value secret? If yes, it will use a
            password input.
    '''
    prompt = input
    if secret:
        import getpass
        prompt = getpass.getpass
    return prompt(':: {} '.format(color_(question, color)))

