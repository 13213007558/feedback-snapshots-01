``aiosasl``, pure python generic asyncio SASL library
#####################################################

.. image:: https://github.com/horazont/aiosasl/workflows/CI/badge.svg
  :target: https://github.com/horazont/aiosasl/actions?query=workflow%3ACI+branch%3Adevel

.. image:: https://coveralls.io/repos/github/horazont/aiosasl/badge.svg?branch=devel
  :target: https://coveralls.io/github/horazont/aiosasl?branch=devel

``aiosasl`` provides a generic, asyncio-based SASL library. It can be used with
any protocol, provided the necessary interface code is provided by the
application or protocol implementation.

Dependencies
------------

* Python ≥ 3.5

Supported SASL mechanisms
-------------------------

* ``PLAIN``: authenticate with plaintext password (RFC 4616)
* ``ANONYMOUS``: anonymous "authentication" (RFC 4505)
* ``SCRAM-SHA-1`` and ``SCRAM-SHA-256`` (and the ``-PLUS`` variants with
  channel binding): Salted Challenge Response Authentication (RFC 5802)

Documentation
-------------

Official documentation can be built with sphinx and is available online
`on our servers <https://docs.zombofant.net/aiosasl/devel/>`_.

Authorization identities (``authzid``)
--------------------------------------

``PLAIN``, ``SCRAM`` and ``SCRAM-PLUS`` accept an optional ``authzid``
argument.  It asks the server to let the authenticated account act as another
identity.  The value is a request only; the identity used after a successful
exchange must come from a trusted server result or an explicit application
mapping (see ``aiosasl.resolve_authorization``).  Omitting ``authzid`` keeps
the existing wire format.

See ``examples/authzid_demo.py`` for allowed and refused delegation cases.

Supported channel binding methods
---------------------------------

* ``tls-unique`` and ``tls-server-end-point`` with a pyOpenSSL connection
* all methods supported by the Python standard library when using the
  ``ssl`` module
