import oidcat
from . import util, CLIBase



class Core(CLIBase):
    '''An example Keycloak admin CLI.

    This is not meant to be fully featured, it is purely
    '''
    def __init__(self, username=None, password=None, host=None, **kw):
        self._CLI_CONFIG = '~/.{}-{}-cli-config'.format(
            self.__class__.__module__, self.__class__.__name__).lower()

        self.sess = oidcat.Session(
            host, username=username, password=password,
            client_id='admin-cli', client_secret=None,
            ask=True, store=self._CLI_CONFIG, **kw)
        self._authurl = self.sess.access.well_known['issuer'].replace(
            '/auth/realms', '/auth/admin/realms')

    def url(self, *path, **kw):
        '''Make an API url.'''
        return oidcat.util.asurl(self._authurl, *path, **kw)

    def _get(self, url, **kw):
        print('get:', url)
        data = oidcat.response_json(self.sess.get(url), **kw)
        return data


    class users(util.Nest):
        BASE = 'users'
        def ls(self, search=None, username=None,
                email=None, firstName=None, lastName=None,
                first=None, max=None, briefRepresentation=None):
            return self._get(self.url(
                self.BASE, search=search, username=username,
                email=email, firstName=firstName, lastName=lastName,
                first=first, max=max, briefRepresentation=briefRepresentation))

        def get(self, id):
            return self._get(self.url(self.BASE, id))

        def groups(self, id, search=None, max=None, first=None):
            return self._get(self.url(self.BASE, id, 'groups', search=search, max=max, first=first))

        def roles(self, id):
            return self._get(self.url(self.BASE, id, 'role-mappings'))

        def realm_roles(self, id):
            return self._get(self.url(self.BASE, id, 'role-mappings/realm'))

        def available_realm_roles(self, id):
            return self._get(self.url(self.BASE, id, 'role-mappings/realm/available'))

        def effective_realm_roles(self, id):
            return self._get(self.url(self.BASE, id, 'role-mappings/realm/composite'))

        def attack_detection(self, id):
            return self._get(self.url('attack-detection/brute-force/users', id))

    class groups(util.Nest):
        def ls(self, search=None, max=None, first=None):
            return self._get(self.url('groups', search=search, max=max, first=first))

        def get(self, id):
            return self._get(self.url('groups', id))

        def users(self, id, max=None, first=None):
            return self._get(self.url('groups', id, 'members', max=max, first=first))

        def roles(self, id):
            return self._get(self.url('groups', id, 'role-mappings'))

        def realm_roles(self, id):
            return self._get(self.url('groups', id, 'role-mappings/realm'))

        def available_realm_roles(self, id):
            return self._get(self.url('groups', id, 'role-mappings/realm/available'))

        def effective_realm_roles(self, id):
            return self._get(self.url('groups', id, 'role-mappings/realm/composite'))

        def permissions(self, id):
            return self._get(self.url('groups', id, 'management/permissions'))

    class roles(util.Nest):
        def ls(self):
            return self._get(self.url('roles'))

        def get(self, name):
            return self._get(self.url('roles', name))

        def users(self, name):
            return self._get(self.url('roles', name, 'users'))

    class clients(util.Nest):
        def ls(self):
            return self._get(self.url('clients'))

        def get(self, id):
            return self._get(self.url('clients', id))

        def secret(self, id):
            return self._get(self.url('clients', id, 'client-secret'))

        def default_scopes(self, id):
            return self._get(self.url('clients', id, 'default-client-scopes'))

        def optional_scopes(self, id):
            return self._get(self.url('clients', id, 'optional-client-scopes'))

        def example_token(self, id, scope=None, userId=None):
            return self._get(self.url('clients', id, 'evaluate-scopes/generate-example-access-token', scope=scope, userId=userId))

        def offline_sessions(self, id):
            return self._get(self.url('clients', id, 'offline-sessions'))

        def sessions(self, id):
            return self._get(self.url('clients', id, 'user-sessions'))

        def service_account(self, id):
            return self._get(self.url('clients', id, 'service-account-user'))

    class scopes(util.Nest):
        def ls(self):
            return self._get(self.url('client-scopes'))

        def get(self, id):
            return self._get(self.url('client-scopes', id))

        def mappers(self, id):
            return self._get(self.url('client-scopes', id, 'protocol-mappers/models'))

        def mapper(self, id, mapId):
            return self._get(self.url('client-scopes', id, 'protocol-mappers/models', mapId))

    class components(util.Nest):
        def ls(self):
            return self._get(self.url('components'))

        def get(self, id):
            return self._get(self.url('components', id))

        def subtypes(self, id):
            return self._get(self.url('components', id, 'sub-component-types'))

    def realm(self):
        return self._get(self.url())

    def keys(self):
        return self._get(self.url('keys'))

    def admin_events(self):
        return self._get(self.url('admin-events'))

    def events(self, client=None, dateFrom=None, dateTo=None, first=None, ipAddress=None, max=None, type=None, user=None):
        return self._get(self.url(
            'events', client=client, dateFrom=dateFrom, dateTo=dateTo,
            ipAddress=ipAddress, user=user, first=first, max=max, type=type))

    def client_session_stats(self):
        return self._get(self.url('client-session-stats'))

    def default_groups(self, id):
        return self._get(self.url('default-groups'))

    def default_scopes(self, id):
        return self._get(self.url('default-default-client-scopes'))

    def optional_scopes(self, id):
        return self._get(self.url('default-optional-client-scopes'))

    # def default_groups(self):
    #     return self._get(self.url('default-groups'))





class CLI(Core):
    class users(Core.users):
        ls = util.cli_formatted(Core.users.ls, 'firstName|lastName,username,id,...')
        get = util.cli_formatted(Core.users.get)
        groups = util.cli_formatted(Core.users.groups)
        roles = util.cli_formatted(Core.users.roles)

    class groups(Core.groups):
        ls = util.cli_formatted(Core.groups.ls)
        get = util.cli_formatted(Core.groups.get)
        users = util.cli_formatted(Core.groups.users)
        roles = util.cli_formatted(Core.groups.roles)
        realm_roles = util.cli_formatted(Core.groups.realm_roles)
        available_realm_roles = util.cli_formatted(Core.groups.available_realm_roles)
        effective_realm_roles = util.cli_formatted(Core.groups.effective_realm_roles)

    class roles(Core.roles):
        ls = util.cli_formatted(Core.roles.ls, 'name,id,description,...', drop={'containerId'}, sort='name')
        get = util.cli_formatted(Core.roles.get)
        users = util.cli_formatted(Core.roles.users)

    realm = util.cli_formatted(Core.realm)
    admin_events = util.cli_formatted(Core.admin_events)
    events = util.cli_formatted(Core.events)
    client_session_stats = util.cli_formatted(Core.client_session_stats)


def main():
    import fire
    fire.Fire(CLI())


if __name__ == '__main__':
    main()
