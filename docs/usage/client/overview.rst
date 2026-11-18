===============
Client Overview
===============

Creating a client
=================

There is not much to it: Create a :class:`asyncua.client.client.Client` and your
ready to go. The url is usually something like ``opc.tcp:\\<server>:4840``, but you
might check your server documentation to make sure your server runs actually on this port.

Connecting to a server
======================

.. todo:: Show different examples, with / without security, ...


Learn more about the server
===========================

.. todo:: Things to show here: Namespaces, loading data type definitions, ...

Browsing and accessing nodes
============================

.. todo:: Usage of shortcut objects (root, objects, ...)

Selecting endpoints from discovery
==================================

OPC UA discovery proposes endpoints; it does not authorize the server.  An
``EndpointDescription.SecurityLevel`` value is a server-declared diagnostic
byte and must not be used as an authentication result.  Select a target from a
deployment-owned identity instead:

.. code-block:: python

    from asyncua import Client
    from asyncua.client.endpoint_security import (
        EndpointOrigin, EndpointSecurityPolicy, ServerIdentity,
    )
    from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

    url = "opc.tcp://server.example:4840/secure"
    identity = ServerIdentity(
        "urn:example:server",
        certificate=trusted_server_certificate,      # or trust_store=..., at least one
        allowed_origins=frozenset({EndpointOrigin.parse(url)}),
    )
    policy = EndpointSecurityPolicy(
        identity=identity,
        allowed_security_policy_uris=frozenset({SecurityPolicyBasic256Sha256.URI}),
    )

    client = Client(url)
    client.set_user("operator")
    client.set_password("secret")
    client.credential_release_callback = lambda selected: audit(selected.describe())
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=client_certificate,
        private_key=client_private_key,
        endpoint_security_policy=policy,
    )
    await client.connect()

The strict path performs these checks before a user token can be built:

* the endpoint address must equal the configured connection target and stay in
  ``allowed_origins``;
* ``EndpointDescription.Server.ApplicationUri`` must equal the configured
  application URI;
* the endpoint certificate must match the pinned certificate or validate
  against the configured :class:`~asyncua.crypto.truststore.TrustStore`, and
  its SubjectAltName must contain the configured application URI;
* the security policy must be in the allowed set, the mode must be at least
  ``SignAndEncrypt`` when credentials are configured, and the endpoint must
  advertise an encrypted ``UserName`` token policy;
* ``CreateSession`` must return the same certificate and an
  ``ServerEndpoints`` entry with the same policy, mode, origin, application URI
  and certificate.  A changed response fails the session; there is no fallback
  to ``SecurityPolicyNone``.

``client.last_connection_target`` records the address actually dialed.
``client.credential_release_callback`` fires only after the channel and
``CreateSession`` evidence above succeeded, immediately before the password is
encrypted into the ``ActivateSession`` token.

Discovery can tell you which endpoints a server advertises, its claimed
application URI/certificate and token policies.  The trust anchor, the expected
application URI, the allowed network origins and the decision that a password
may be released must come from deployment configuration.

See ``examples/client-auto-endpoint-security.py`` for accept, reject and
missing-trust runs.
