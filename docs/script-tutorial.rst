Tutorial - Simple Polling Script
=============================================

A simple script that polls an API endpoint ``https://api.myserver.com/api/data``, where the endpoint is protected using an authorization server ``https://auth.myserver.com``.

Installation / Setup
-----------------------

This assumes that you have a OIDC authorization provider running at ``auth.myserver.com``. I have only tested this library with Keycloak.

This assumes that you have some API that you want to query at ``api.myserver.com``.

.. code-block:: bash

    pip install oidcat

The Code
-----------

.. code-block:: python

    import traceback
    import oidcat

    AUTH_HOST = 'auth.myserver.com'  # e.g. keycloak server
    API_HOST = 'api.myserver.com'  # e.g. flask server
    
    def run(interval=30):
        # make environment variable namespace
        env = oidcat.util.Env('myscript_')

        # create session object
        sess = oidcat.Session(
            AUTH_HOST, 
            # get username and password from 
            # MYSCRIPT_USERNAME and MYSCRIPT_PASSWORD
            env.username, env.password,
            # get keycloak client_id and client_secret from 
            # MYSCRIPT_CLIENT_ID and MYSCRIPT_CLIENT_SECRET
            client_id=env.client_id, client_secret=env.client_secret)

        # get the query url
        url = oidcat.asurl(API_HOST, 'api/data')

        # run the query continuously at some interval
        while True:
            t0 = time.time()

            try:
                # query the data
                data = oidcat.response_json(sess.get(url))
                # then do something with it
                handle_data(data)
            except Exception:
                # just log exceptions and keep going
                traceback.print_exc()
            
            # sleep for the remaining time
            time.sleep(max(interval - (time.time() - t0), 0))

    def handle_data(data):
        # do something with the data
        print(data)

    if __name__ == '__main__':
        import fire
        fire.Fire(run)


To Use It:
------------

Add this to your environment somewhere (e.g. ``~/.bashrc``). 

.. code-block:: bash
    
    export MYSCRIPT_USERNAME=...
    export MYSCRIPT_PASSWORD=...
    export MYSCRIPT_CLIENT_ID=...
    export MYSCRIPT_CLIENT_SECRET=...

Then to run: 

.. code-block:: bash

    python myscript.py

    python myscript.py --interval 120  # run every 2 mins


.. note::
    NOTE-TO-SELF: how to support ``.env`` files?

    maybe I could include a util from here: https://stackoverflow.com/questions/40216311/reading-in-environment-variables-from-an-environment-file
