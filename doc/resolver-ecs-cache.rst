.. _resolver-ecs-cache:

ECS-Aware Caching
=================

A resolver that forwards EDNS Client Subnet (ECS,
`RFC 7871 <https://tools.ietf.org/html/rfc7871>`_) cannot use the
ordinary ``(name, rdtype, rdclass)`` cache key, because an answer
produced for one client subnet must never be served to a client in a
different subnet.  The :mod:`dns.ecscache` module provides a
self-contained, security-focused adapter that keeps per-subnet answers
isolated.

Reuse is decided from the *scope prefix length* the upstream resolver
returns in its response, not from treating the raw ECS option bytes as a
cache key:

* a response scope of zero, or a response with no ECS option at all, is
  globally reusable and serves every client;
* otherwise the answer is stored against the scope network the server
  asserted, and a lookup returns the longest matching scope that covers
  the client's masked address;
* by default a response scope that reaches beyond the queried source
  prefix is clamped back to that prefix, so an upstream cannot widen the
  reach of an answer past the network actually asked about
  (:class:`~dns.ecscache.WiderScopePolicy.CLAMP`);
* malformed ECS options and address-family mismatches are fail-closed:
  the message is never cached;
* the full client address is never retained.  Every client address is
  masked to its source prefix immediately, and only the resulting network
  is ever stored or forwarded.

Audit callbacks receive :class:`~dns.ecscache.ECSEvent` values whenever
host bits are masked, a scope is clamped, an answer is treated as global,
or a malformed option is rejected.

.. autoclass:: dns.ecscache.ECSData
   :members:

.. autoclass:: dns.ecscache.ParsedECS
   :members:

.. autoclass:: dns.ecscache.ECSEvent
   :members:

.. autoclass:: dns.ecscache.WiderScopePolicy
   :members:

.. autoclass:: dns.ecscache.NoECSPolicy
   :members:

.. autoclass:: dns.ecscache.ECSCache
   :members:

.. autoclass:: dns.ecscache.ECSResolver
   :members:

.. autoexception:: dns.ecscache.ECSError

.. autoexception:: dns.ecscache.ECSMalformed

.. autofunction:: dns.ecscache.client_subnet

.. autofunction:: dns.ecscache.parse_ecs_wire

.. autofunction:: dns.ecscache.extract_ecs

.. autofunction:: dns.ecscache.make_ecs_option
