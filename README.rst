.. image:: https://github.com/AmadeusITGroup/AutoSSL/actions/workflows/test.yaml/badge.svg?branch=master
    :target: https://github.com/AmadeusITGroup/AutoSSL/actions

.. image:: https://coveralls.io/repos/AmadeusITGroup/AutoSSL/badge.svg?branch=master
    :target: https://coveralls.io/r/AmadeusITGroup/AutoSSL?branch=master

.. image:: https://badge.fury.io/py/autossl.svg
    :target: https://badge.fury.io/py/autossl

.. image:: https://readthedocs.org/projects/autossl/badge?version=latest
    :target: https://autossl.readthedocs.io?badge=latest

.. image:: https://pepy.tech/badge/autossl
    :target: https://pepy.tech/badge/autossl


:AutoSSL:          Python module to automate SSL certificates monitoring, renewal and deployment
:Copyright:        Copyright (c) 2019 Amadeus sas
:License:          `MIT <https://github.com/AmadeusITGroup/AutoSSL/blob/master/LICENSE>`_
:Documentation:    https://autossl.readthedocs.io
:Development:      https://github.com/AmadeusITGroup/AutoSSL

What
----
`autossl` is a module for Python 2.7+/3.5+ that can be used to to automate SSL certificate monitoring, renewal and deployment.

This module can be customized with plugins mechanism to support any type of:

* **server**: where the certificate is deployed, can be 1 or more server, potentially of different types
* **storage**: where to store your artifacts (private key, public certificate, ...)
* **tracking mechanism**: how to track renewal process (ticket creation)
* **renewal method**: how to get a new certificate (local CA, ACME protocol, ....)

It's providing a command line interface with simple actions: `check`, `renew`, `deploy`.
All configuration is provided thanks to blueprints in Yaml

It can then be run by any tool able to use a command line (cron, jenkins pipeline, ...) to manage all your certificates from a central place.

Installation
------------
For a basic installation, just run

    $ pip install autossl

to support optional features, you may need extra dependencies, for that install autossl with corresponding `keyword`:

    $ pip install autossl[keyword]

See available `keywords` and associated extra dependencies in table below:

+------------+--------------------------+--------------------------------------+
|  keyword   |  additional dependencies |  extra features                      |
+============+==========================+======================================+
|   all      |    all packages below    |  all features below                  |
+------------+--------------------------+--------------------------------------+
|   acme     |    acme                  |  renewal using ACME protocol         |
+------------+--------------------------+--------------------------------------+
|   git      |    GitPython             |  artifacts storage in git repository |
+------------+--------------------------+--------------------------------------+

Tests
-----
tests require few more python packages. To install them, run:

    $ pip install -r requirements_dev.txt

Clone the repository, then to execute the test suite with your current python version, run:

    $ pytest -sv tests

Contributing
------------

Bug Reports
^^^^^^^^^^^
Bug reports are hugely important! Before you raise one, though,
please check through the `GitHub issues <https://github.com/AmadeusITGroup/AutoSSL/issues>`_,
both open and closed, to confirm that the bug hasn't been reported before.

Feature Requests
^^^^^^^^^^^^^^^^
If you think a feature is missing and could be useful in this module, feel free to raise a feature request through the
`GitHub issues <https://github.com/AmadeusITGroup/AutoSSL/issues>`_

Code Contributions
^^^^^^^^^^^^^^^^^^
When contributing code, please follow `this project-agnostic contribution guide <http://contribution-guide.org/>`_.
