Tutorial - Creating a CLI
==========================
Here we are going to create a CLI that wraps a REST API.

This should show you how easy it is to get up and off the ground!


Installation / Setup
-----------------------

This assumes that you have a OIDC authorization provider running at ``auth.myserver.com``. I have only tested this with Keycloak.

This assumes that you have some API that you want to query at ``api.myserver.com``. The example endpoints used here are:

 - ``api.myserver.com/api/data`` which returns a list of dictionaries.
 - ``api.myserver.com/api/data/item/<item_id>`` which returns a single dictionary corresponding to that item ID.

.. code-block:: bash

    pip install oidcat

The Code
-----------

.. code-block:: python

    import oidcat
    
    AUTH_HOST = 'auth.myserver.com'  # e.g. keycloak server
    API_HOST = 'api.myserver.com'  # e.g. flask server
    
    CLIENT_ID = 'some-public-keycloak-client'
    
    class MyCLI:
        def __init__(self, trusted=None):
            # create a session object.
            self.sess = oidcat.Session(
                AUTH_HOST, client_id=CLIENT_ID, 
                # if we don't have credentials, we want it to 
                # ask via the terminal
                ask=True,
                # we typically want an offline token so that 
                # we can stay logged in for a long time.
                # this is meant for convenience on your personal computer.
                # don't enable on public systems.
                offline=True if trusted else None, 
                # this stores tokens and configuration so that it can 
                # be persisted between CLI calls.
                store='~/.mycli/config'
            )

        # utilities
    
        def url(self, *path, **params):
            '''A helper to create an API url from a path.'''
            # e.g. https://api.myserver.com/api/some/path?some=param
            return oidcat.util.asurl(API_HOST, 'api', *path, **params)

        # basic CLI functionality
    
        def login(self):
            self.sess.login()
    
        def logout(self):
            self.sess.logout()

        # custom endpoints (the interesting part)
    
        def data_ls(self):
            '''Show the list of data.'''
            self.sess.require_login()
            # NOTE: you don't have to use `oicat.response_json`, 
            #       you can just use `.json()` if you want.
            #       it just provides some builtin error handling for you.
            data = oicat.response_json(self.sess.get(self.url('/data')))
            for i, d in enumerate(data):
                print('item {}: {}'.format(i, d))
    
        def item(self, data_id):
        '''Get the data for a specific ID.'''
            self.sess.require_login()
            data = oicat.response_json(self.sess.get(self.url('/data/item', data_id)))
            return data
    
    if __name__ == '__main__':
        import fire
        fire.Fire(MyCLI)
    

To Use It:
------------

.. code-block:: bash

    # you can explicitly login/logout like this
    python mycli.py login
    python mycli.py logout

    # list data (calls `MyCLI.data_ls()`)
    python mycli.py data-ls
    # NOTE: it will ask you for credentials if you are not already logged in.

    # get a specific item by id (calls `MyCLI.item('data-id-asodfinasdofia')`)
    python mycli.py item data-id-asodfinasdofia