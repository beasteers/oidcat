Tutorial - Creating a Authenticated Server
=============================================

This is a basic version of how you can protect a server's endpoints using tokens and user roles.

Author Note
-------------

I'm still workshopping the best "required roles" interface. At first, I liked the decorator pattern
because it let's you know the roles statically. But as I was further developing 
a test server, I started to realize that it was getting too complicated to define the roles
that way and I moved to use this much more often:

.. code-block:: python

    token = oidc.valid_token()
    read_all, read_mine = token.check_roles('read-all-things', 'read-my-things')
    if read_all:
        return everythingggg
    else:
        return only_a_few_things



The Code
-----------

.. code-block:: python

    import os
    import flask
    import oidcat.server


    app = flask.Flask(__name__)
    app.config.update(
        # Create the client configuration 
        # (makes request to the authorization server's well-known url)
        OIDC_CLIENT_SECRETS=oidcat.util.with_well_known_secrets_file(
            'auth.myapp.com', 'myclient', 'supersecret'),

        # or:

        # # Create keycloak client configuration 
        # # (this all happens locally)
        # OIDC_CLIENT_SECRETS=oidcat.util.with_keycloak_secrets_file(
        #     'auth.myapp.com', 'myclient', 'supersecret', 'myrealm'),
    )

    # create the oidc object and initialize it with the app
    oidc = oidcat.server.OpenIDConnect(app, 'creds.db')


    # various forms of protecting endpoints

    @app.route('/')
    @oidc.require_login
    def index():  # this doesn't check any permissions, just that someone has an account and is logged in
        '''This will redirect you to a login screen.'''
        return flask.jsonify({'message': 'Welcome!'})

    @app.route('/edit')
    def edit():
        token = oidc.valid_token()
        # this will not raise an error if the token has at least one of these
        is_editor, is_manager = token.check_roles('editor', 'manager')
        return flask.jsonify({'message': 'you did something!'})

    @app.route('/view')
    def view():
        token = oidc.valid_token()
        is_viewer = token.check_roles('viewer')
        return flask.jsonify({'message': 'something interesting!'})

    # using the decorator

    @app.route('/ultimatepower')
    @oidc.accept_token(realm_role='admin')  # realm role
    def ultimatepower():
        return flask.jsonify({'message': 'mwahahah!'})

    @app.route('/ultimatepower2')
    @oidc.accept_token(client_role='admin')  # client role
    def ultimatepower2():
        return flask.jsonify({'message': 'mwahahah!'})

    @app.route('/ultimatepoweruwu')
    @oidc.accept_token(scopes=['admin'])  # required scopes
    def ultimatepower3():
        return flask.jsonify({'message': 'mwahahah!'})


    if __name__=='__main__':
        app.run(host='0.0.0.0', port=PORT, debug=True)


To Run:

.. code-block:: python

    python myserver.py