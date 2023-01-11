import sys
import json
import oidcat
from . import util



class Keycloak:
    '''An example Keycloak admin CLI.

    '''
    def __init__(self, username=None, password=None, host=None, **kw):
        self._CLI_CONFIG = '~/.{}-{}-cli-config'.format(
            self.__class__.__module__, self.__class__.__name__).lower()

        self.sess = oidcat.Session(
            host, username=username, password=password,
            ask=True, store=self._CLI_CONFIG, **kw)
        self.sess.__doc__ = "The request session"
        self._authurl = self.sess.access.well_known['issuer'].replace(
            '/realms', '/admin/realms')

    def __str__(self, include_methods=True):
        methods = "".join([
            f'\n  {k}: {f.__doc__ or ""}' 
            for k, f in ({**vars(self.__class__), **vars(self)}).items()
            if not k.startswith('_')
        ]) if include_methods else ""
        return f'{self.__class__.__name__}\n{self.__doc__}\n{self.sess}\n{methods}'

    def _url(self, *path, **kw):
        '''Make an API url.'''
        return oidcat.util.asurl(self._authurl, *path, **kw)

    def _request(self, method, url, **kw):
        print(f'{method.upper()} {url}', file=sys.stderr)
        return oidcat.response_json(self.sess.request(method, url), **kw)

    def _get(self, *a, **kw):
        return self._request('get', *a, **kw)

    def login(self, *a, **kw):
        '''Login'''
        # print(self.sess.access.well_known)
        self.sess.login(*a, **kw)

    def logout(self, *a, **kw):
        '''Logout'''
        self.sess.logout(*a, **kw)

    class users(util.Nest):
        '''User management'''
        def ls(self, search=None, username=None,
                email=None, firstName=None, lastName=None,
                first=None, max=None, briefRepresentation=None):
            return self._get(self._url(
                'users', search=search, username=username,
                email=email, firstName=firstName, lastName=lastName,
                first=first, max=max, briefRepresentation=briefRepresentation))

        def get(self, id):
            return self._get(self._url('users', id))

        def groups(self, id, search=None, max=None, first=None):
            return self._get(self._url('users', id, 'groups', search=search, max=max, first=first))

        def roles(self, id):
            return self._get(self._url('users', id, 'role-mappings'))

        def realm_roles(self, id):
            return self._get(self._url('users', id, 'role-mappings/realm'))

        def available_realm_roles(self, id):
            return self._get(self._url('users', id, 'role-mappings/realm/available'))

        def effective_realm_roles(self, id):
            return self._get(self._url('users', id, 'role-mappings/realm/composite'))

        def attack_detection(self, id):
            return self._get(self._url('attack-detection/brute-force/users', id))

    class groups(util.Nest):
        '''Group management'''
        def ls(self, search=None, max=None, first=None):
            return self._get(self._url('groups', search=search, max=max, first=first))

        def get(self, id):
            return self._get(self._url('groups', id))

        def users(self, id, max=None, first=None):
            return self._get(self._url('groups', id, 'members', max=max, first=first))

        def roles(self, id):
            return self._get(self._url('groups', id, 'role-mappings'))

        def realm_roles(self, id):
            return self._get(self._url('groups', id, 'role-mappings/realm'))

        def available_realm_roles(self, id):
            return self._get(self._url('groups', id, 'role-mappings/realm/available'))

        def effective_realm_roles(self, id):
            return self._get(self._url('groups', id, 'role-mappings/realm/composite'))

        def permissions(self, id):
            return self._get(self._url('groups', id, 'management/permissions'))

    class roles(util.Nest):
        '''Role management'''
        def ls(self):
            return self._get(self._url('roles'))

        def get(self, name):
            return self._get(self._url('roles', name))

        def users(self, name):
            return self._get(self._url('roles', name, 'users'))

    class clients(util.Nest):
        '''Client management'''
        def ls(self):
            return self._get(self._url('clients'))

        def get(self, id):
            return self._get(self._url('clients', id))

        def secret(self, id):
            return self._get(self._url('clients', id, 'client-secret'))

        def default_scopes(self, id):
            return self._get(self._url('clients', id, 'default-client-scopes'))

        def optional_scopes(self, id):
            return self._get(self._url('clients', id, 'optional-client-scopes'))

        def example_token(self, id, scope=None, userId=None):
            return self._get(self._url('clients', id, 'evaluate-scopes/generate-example-access-token', scope=scope, userId=userId))

        def offline_sessions(self, id):
            return self._get(self._url('clients', id, 'offline-sessions'))

        def sessions(self, id):
            return self._get(self._url('clients', id, 'user-sessions'))

        def service_account(self, id):
            return self._get(self._url('clients', id, 'service-account-user'))

    class scopes(util.Nest):
        '''Client scope management'''
        def ls(self):
            return self._get(self._url('client-scopes'))

        def get(self, id):
            return self._get(self._url('client-scopes', id))

        def mappers(self, id):
            return self._get(self._url('client-scopes', id, 'protocol-mappers/models'))

        def mapper(self, id, mapId):
            return self._get(self._url('client-scopes', id, 'protocol-mappers/models', mapId))

    class components(util.Nest):
        def ls(self):
            return self._get(self._url('components'))

        def get(self, id):
            return self._get(self._url('components', id))

        def subtypes(self, id):
            return self._get(self._url('components', id, 'sub-component-types'))

    def realm(self):
        return self._get(self._url())

    def keys(self):
        return self._get(self._url('keys'))

    def admin_events(self):
        return self._get(self._url('admin-events'))

    def events(self, client=None, dateFrom=None, dateTo=None, first=None, ipAddress=None, max=None, type=None, user=None):
        return self._get(self._url(
            'events', client=client, dateFrom=dateFrom, dateTo=dateTo,
            ipAddress=ipAddress, user=user, first=first, max=max, type=type))

    def client_session_stats(self):
        return self._get(self._url('client-session-stats'))

    def default_groups(self, id):
        return self._get(self._url('default-groups'))

    def default_scopes(self, id):
        return self._get(self._url('default-default-client-scopes'))

    def optional_scopes(self, id):
        return self._get(self._url('default-optional-client-scopes'))

    # def default_groups(self):
    #     return self._get(self._url('default-groups'))





# class CLI(Core):
#     class users(Core.users):
#         ls = util.cli_formatted(Core.users.ls, 'firstName|lastName,username,id,...')
#         get = util.cli_formatted(Core.users.get)
#         groups = util.cli_formatted(Core.users.groups)
#         roles = util.cli_formatted(Core.users.roles)

#     class groups(Core.groups):
#         ls = util.cli_formatted(Core.groups.ls)
#         get = util.cli_formatted(Core.groups.get)
#         users = util.cli_formatted(Core.groups.users)
#         roles = util.cli_formatted(Core.groups.roles)
#         realm_roles = util.cli_formatted(Core.groups.realm_roles)
#         available_realm_roles = util.cli_formatted(Core.groups.available_realm_roles)
#         effective_realm_roles = util.cli_formatted(Core.groups.effective_realm_roles)

#     class roles(Core.roles):
#         ls = util.cli_formatted(Core.roles.ls, 'name,id,description,...', drop={'containerId'}, sort='name')
#         get = util.cli_formatted(Core.roles.get)
#         users = util.cli_formatted(Core.roles.users)

#     realm = util.cli_formatted(Core.realm)
#     admin_events = util.cli_formatted(Core.admin_events)
#     events = util.cli_formatted(Core.events)
#     client_session_stats = util.cli_formatted(Core.client_session_stats)



def main():
    import fire
    import rich
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    from rich.console import Console
    import pydoc
    import yamtable

    def is_table(d):
        return isinstance(d, list) and d and all(di is None or isinstance(di, dict) for di in d)
    def richyam(data, tree=None):
        # if not tree:
        #     tree = Tree("")
        if is_table(data):
            cols = list(data[0])
            t = Table()
            for c in cols:
                t.add_column(c, min_width=8)
            for d in data:
                t.add_row(*[richyam(d.get(c)) for c in cols])
            data = t
            if tree:
                tree.add(data)
                return tree
            else:
                return data
        elif isinstance(data, dict):
            tree = tree or Tree("")
            for k, v in data.items():
                b = tree.add(k)
                richyam(v, b)
            return tree
        elif isinstance(data, (list, tuple)):
            if data:
                tree = tree or Tree("")
                for d in data:
                    b = tree.add('-')
                    richyam(d, b)
                return
        elif isinstance(data, bool):
            data = yamtable.BOOLS['rose'][int(not bool(data))]
        if data is None:
            return
        if tree:
            tree.add(str(data))
            return tree
        else:
            return str(data)

    def serialize(x):
        class Pager:
            def show(self, x):
                return pydoc.pipepager(x, 'less -RS')
        
        xx = richyam(x)
        if xx is not None:
            console = Console(width=1000000000)
            with console.pager(Pager()):
                console.print(xx)
        return x

    fire.Fire(Keycloak, serialize=serialize)
    # fire.Fire(Keycloak, serialize=lambda x: pydoc.pager(yam.dump(x)))
    # fire.Fire(Keycloak, serialize=rich.print)


if __name__ == '__main__':
    main()
