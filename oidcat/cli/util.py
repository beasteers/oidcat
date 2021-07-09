import oidcat
import fnmatch
import functools

# top-level functions


def cli_formatted(*atb, sort=None, extra=None, **kwtb):
    '''This handles most output formats including nested dictionaries,
    tabular data (list of dicts), and exceptions.'''
    def outer(func):
        @functools.wraps(func)
        def inner(*a, sort=sort, raw=False, **kw):
            data = func(*a, **kw)
            data = handle_data(data, sort=sort, extra=extra)
            if raw:
                return data
            return yamltable(data, *atb, **kwtb)
        return inner
    if atb and callable(atb[0]):
        func, atb = atb[0], atb[1:]
        return outer(func)
    return outer


def yamltable(d, *a, indent=0, width=2, depth=-1, _keys=(), **kw):
    '''Format data as yaml. Any list of dicts will be rendered as a table.

    Arguments:
        *a: positional arguments for ``astable``.
        indent (int): the indent index (how many tabs?).
        width (int): tab width.
        depth (int): How many depths to render? If -1, traverse all.
        **kw: keyword arguments for ``astable``.

    Returns:
        output (str): The formatted data.
    '''
    if depth:
        if isinstance(d, dict):
            d = '\n'.join('{}: {}'.format(k, yamltable(
                    d[k], *a, indent=indent+1,
                    width=width, depth=depth-1,
                    _keys=_keys + (k,), **kw))
                for k in d)

        if isinstance(d, list):
            if all(di is None or isinstance(di, dict) for di in d):
                d = astable(d, *a, **kw)
            else:
                d = '\n'.join([' - {}'.format(di) for di in d])

    d = str(d)
    if indent and len(d.splitlines()) > 1:
        d = '\n' + _indent(d, indent=indent > 0, width=width)
    return d


# def cli_formatted_class(cls, ignore_names=(), ignore_types=(), **kw):
#     ignore_names = oidcat.util.aslist(ignore_names)
#     ignore_types = oidcat.util.aslist(ignore_types)
#     attrs = {}
#     for k in dir(cls):
#         func = getattr(cls, k)
#         if isinstance(func, type) and not issubclass(func, ignore_types):
#             attrs
#         if callable(func) and k not in ignore_names and (
#                 not ignore_types or not isinstance(func, ignore_types)):
#             pass

#     return type(cls.__name__, (cls,), {
#         k: cli_formatted(func, **kw)
#         for k, func in all_attrs
        
#     })


# boolean display

BOOLS = {
    'moon': ['🌖', '🌒'],
    'full-moon': ['🌕', '🌑'],
    'rose': ['🌹', '🥀'],
    'rainbow': ['🌈', '☔️'],
    'octopus': ['🐙', '🐍'],
    'virus': ['🔬', '🦠'],
    'party-horn': ['🎉', '💥'],
    'party-ball': ['🎊', '🧨'],

    'relieved': ['😅', '🥺'],
    'laughing': ['😂', '😰'],
    'elated': ['🥰', '🤬'],
    'fleek': ['💅', '👺'],
    'thumb': ['👍', '👎'],
    'green-heart': ['💚', '💔'],
    'circle': ['🟢', '🔴'],
    'green-check': ['✅', '❗️'],
    'TF': ['T', 'F'],
    'tf': ['t', 'f'],
    'YN': ['Y', 'N'],
    'yn': ['y', 'n'],
    'check': ['✓', ''],
    'checkx': ['✓', 'x'],
}

CURRENT_BOOL = 'rose'

def register_bool(name, yes, no):
    '''Add new bool icons. yes when True, no when False.'''
    BOOLS[name] = [yes, no]

def set_bool_icon(name):
    '''Set the default bool icon.'''
    global CURRENT_BOOL
    CURRENT_BOOL = name

def get_bool(name=None):
    '''Get the bool icon.'''
    return BOOLS[name or CURRENT_BOOL]




def handle_data(data, extra=None, sort=None, **filters):
    # handle single entry
    if isinstance(data, dict):
        # check for an errors
        if 'error' in data:
            raise oidcat.RequestError(str(data))
        # otherwise calculate any fields for the data
        return add_fields(data, **(extra or {}))

    if isinstance(data, (list, tuple)):
        # add calculated fields
        data = (add_fields(d, **(extra or {})) for d in data)
        # filter
        data = (
            d for d in data if all(
                compare(d[k], check) if k in d else False
                for k, check in filters.items()))
        # sort
        if sort:
            return sorted(data, key=lambda x: x[sort])
        return list(data)
    return data




def astable(data, cols=None, drop=None, drop_types=(dict, list), **kw):
    '''Format a list of dictionaries as '''
    # short-circuit for non-lists
    if not isinstance(data, (list, tuple)):
        return data
    elif not data:
        return '-- no data --'

    import tabulate

    # get all columns across the data
    all_cols = {c for d in data for c in d if not c.startswith('_')} - set(drop or ())
    if drop_types:
        all_cols = {c for c in all_cols if not any(isinstance(d.get(c), drop_types) for d in data)}
    # default auto columns
    cols = cols or sorted(all_cols)
    # break out columns into a uniform list
    cols = list(_splitnested(cols, ',/|', all_cols))

    # handle leftover columns
    given_cols = {c for ci in cols for cj in ci for c in cj}
    cols = [
        ci for ci_ in cols for ci in (
            [[[c]] for c in sorted(all_cols - given_cols)]
            if ci_ == [['...']] else (ci_,))]

    # convert back to column names
    colnames = ['/'.join('|'.join(cj) for cj in ci) for ci in cols]

    # get data
    rows = [[[[nested_key(d, c, None) for c in cj] for cj in ci] for ci in cols] for d in data]

    # convert to table
    return tabulate.tabulate([[
            '\n'.join([
                '|'.join(str(_cellformat(c, **kw)) for c in subcell)
                for subcell in subrow
            ]) for subrow in row
        ] for row in rows], headers=colnames)


# basic helpers


def _indent(d, indent=0, width=2):
    '''Indent a multi-line string.'''
    return '\n'.join('{}{}'.format(' '*indent*width, l) for l in d.splitlines())


def nested_key(d, k, default=...):
    '''Get a nested key (a.b.c) from a nested dictionary.'''
    for ki in k.split('.'):
        try:
            d = d[ki]
        except (TypeError, KeyError):
            if default is ...:
                raise
            return default
    return d


def _maybesplit(x, ch, strip=True, filter=True):
    '''Coerce a string to a list by splitting by a certain character,
    or skip if already a list.'''
    return [
        x.strip() if strip and isinstance(x, str) else x
        for x in (x.split(ch) if isinstance(x, str) else x)
        if not filter or x]


def _splitnested(cols, seps=',/|', avail=None):
    '''Splits a shorthand column layout into a nested column list.
    e.g.
        'time,max_laeq|avg_laeq/l90|min_laeq,emb_*,...'
        [
            [['time]],
            [
                ['max_laeq', 'avg_laeq'],
                ['l90', 'min_laeq']
            ],
            [['emb_min']], [['emb_max'], ...],
            [['time']], ...  # leftover columns
        ]

    '''
    if not seps:
        yield cols
        return
    sep, nextsep = seps[0], seps[1] if len(seps) > 1 else None
    for x in _maybesplit(cols, sep):
        xs = [x]
        if isinstance(x, str) and not any(s in x for s in seps) and avail and '*' in x:
            xs = sorted(c for c in avail if fnmatch.fnmatch(c, x))

        for xi in xs:  # inner loop handles unpacked glob
            yield list(_splitnested(xi, seps[1:], avail)) if nextsep else xi


def _cellformat(x, bool_icon=None):
    '''Format a cell's value based on its data type.'''
    if isinstance(x, bool):
        BOOL = get_bool(bool_icon)
        return BOOL[0] if x else BOOL[1]
    if isinstance(x, float):
        return '{:,.3f}'.format(x)
    if isinstance(x, list):
        return 'list[{}, {}]'.format(len(x), type(x[0]).__name__ if x else None)
    if isinstance(x, dict):
        return 'dict{{{}}}'.format(len(x))
    if x is None:
        return '--'
    return str(x)




def compare(value, check, wildcard=True):
    '''Compare field value with a commandline check.'''
    str_check = isinstance(check, str)
    if str_check:
        if '||' in check:
            return any(compare(value, chk.strip(), wildcard=wildcard) for chk in check.split('||'))
        if '&&' in check:
            return all(compare(value, chk.strip(), wildcard=wildcard) for chk in check.split('&&'))

    if isinstance(value, set):
        return any(compare(v, check, wildcard=wildcard) for v in value)

    if str_check:
        if isinstance(value, (int, float)):
            # allow range checks
            if check.startswith('<='):
                return value <= float(check[2:].strip())
            if check.startswith('>='):
                return value >= float(check[2:].strip())
            if check.startswith('<'):
                return value < float(check[1:].strip())
            if check.startswith('>'):
                return value > float(check[1:].strip())
            return value == float(check)

        if isinstance(value, str):
            notmatch = check.startswith('!')
            if notmatch:
                check = check[1:]
            matched = (
                fnmatch.fnmatch(value, check) if wildcard else
                check in value)
            return matched != notmatch

    if callable(check):
        return check(value)
    if isinstance(check, bool):
        return bool(value) == bool(check)

    return value == check



def add_fields(data, **fields):
    for k, func in fields.items():
        data[k] = func(data)
    return data


# cli namespacing

class _NestedMetaClass(type):
    def __init__(self, name, bases, attrs):
        super().__init__(name, bases, attrs)
        self.__attr_name__ = '__{}'.format(name)

    def __get__(self, instance, owner=None):
        if instance is None:  # for class based access
            return self
        try:
            return getattr(instance, self.__attr_name__)
        except AttributeError:
            x = self(instance)
            setattr(instance, self.__attr_name__, x)
            return x

    def __set__(self, instance, value):  # This is needed for Fire so that `ismethoddescriptor` is False
        raise TypeError()


class Nest(metaclass=_NestedMetaClass):
    # class A:
    #     x = 10
    #     class nested(Nest):
    #         y = 15
    #         def asdf(self):
    #             return self.__.x + self.x + self.y  # 10 + 10 + y
    # import fire
    # fire.Fire(A())
    #
    # $ a.py nested asdf

    ROOT_ATTRS = True
    def __init__(self, instance):
        root = instance
        if isinstance(instance, Nest):
            root = getattr(instance, '_root_', instance)
        self.__ = instance
        self._root_ = root
        self.__name__ = self.__class__.__name__

    def __getattr__(self, key):
        if not self.ROOT_ATTRS:
            raise KeyError(key)
        return getattr(self.__, key)
