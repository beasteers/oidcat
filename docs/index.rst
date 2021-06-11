.. oidcat documentation master file, created by
   sphinx-quickstart on Sun Jun  6 00:56:45 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

oidcat
======

Simple OIDC Connect Wrapper for use in user facing CLI's or scripts or for server-side resource protection.


OIDC is all so confusing, so I wrote a (small) wrapper package around requests and flask-oidc that provides 
a (slightly) easier interface to protect and connect to private resources.

``flask-oidc`` is not included as a dependency by default because more often than not, you're writing user facing code
not a resource server.

Installation
============
Nice and easy!

.. code-block:: shell

   pip install oidcat


To install the dependencies needed for the server:

.. code-block:: shell

   pip install oidcat[server]


Tutorials
==========
.. toctree::
   :maxdepth: 1

   script-tutorial
   cli-tutorial
   server-tutorial

API Reference
=============
.. toctree::
   :maxdepth: 1

   api
   server
   extra

Contribute
=============
- `Issue tracker <http://github.com/beasteers/oidcat/issues>`_
- `Source code <http://github.com/beasteers/oidcat>`_


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
