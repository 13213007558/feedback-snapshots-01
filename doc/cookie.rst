.. _cookie:

DNS Cookies
===========

DNS Cookies (RFC 7873) are an opt-in UDP anti-spoofing mechanism.  A
client Cookie is sent in the EDNS COOKIE option; a server that supports
Cookies returns both the client Cookie and a server Cookie bound to the
client's address.  A response that echoes the client Cookie and carries
a valid server Cookie is much harder for an off-path attacker to forge
than a bare UDP response matched only by query id and source address.

Cookies are not DNSSEC.  They show that the response came from an
endpoint that saw the client Cookie, and (with a server Cookie) that the
server bound its Cookie to this client.  They do not authenticate the
DNS data, and they do not protect against an on-path attacker.  Use
DNSSEC for data authentication, and DoT/DoH/DoQ when the transport
itself must be protected.

Policy
------

Cookie processing is explicitly enabled by assigning a
:py:class:`dns.cookie.CookiePolicy` to a resolver's *cookie_policy*
attribute, or by passing a policy to a
:py:class:`dns.nameserver.Do53Nameserver`::

    import dns.cookie
    import dns.nameserver
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.cookie_policy = dns.cookie.CookiePolicy()

    # Or, for one nameserver only:
    resolver.nameservers = [
        dns.nameserver.Do53Nameserver(
            "192.0.2.53", 53, dns.cookie.CookiePolicy()
        )
    ]

:py:class:`dns.cookie.CookieMode` selects the policy:

``OPPORTUNISTIC``
    Send a client Cookie and use server Cookies when offered.  A response
    without a server Cookie is accepted, but is marked as unbound and is
    not cached by the resolver.

``REQUIRED``
    Send a client Cookie and require every accepted response to echo it
    and contain a server Cookie.  Other responses raise
    :py:exc:`dns.cookie.CookieError`.

``OFF``
    Do not use Cookies.

A COOKIE option requires EDNS.  If a query does not already have EDNS
enabled, the Cookie policy enables EDNS0 with the default payload for that
query; any EDNS flags, payload, and other options already configured are
preserved.

Endpoint binding and rotation
-----------------------------

The client Cookie is derived with HMAC-SHA256 from a policy secret and
a :py:class:`dns.cookie.Endpoint` key containing the destination address,
the destination port, the transport kind, and the selected source
address (when one is given).  Different upstreams therefore get
different client Cookies, and a server Cookie received from one upstream
is stored only in that upstream's slot.  A server Cookie is never sent
to another endpoint.

When a server returns a new server Cookie, including in a response to a
BADCOOKIE retry, the stored value for that endpoint is replaced.  The
:py:class:`dns.nameserver.Do53Nameserver` retries a stale-cookie
exchange once: if the query used a stored server Cookie and the server
replies with BADCOOKIE plus a fresh server Cookie, it re-sends the query
with the new Cookie.  A BADCOOKIE response that does not echo the client
Cookie or does not carry a usable server Cookie is not retried.

The resolver cache
------------------

An answer from an unprotected UDP Do53 exchange that a Cookie policy
accepted without binding it (no server Cookie) is not placed in the
resolver's answer cache.  TCP fallback and DoT/DoH/DoQ exchanges have
transport protection and are cached normally.  Cache reads also require
the entry to have been stored as cacheable under a Cookie policy.  The
:py:attr:`dns.resolver.Answer.cookie_bound` attribute exposes the result
for a particular answer: ``True`` if the exchange completed binding,
``False`` if it was accepted unbound, and ``None`` if no Cookie policy
was applied.

.. autoclass:: dns.cookie.CookieMode
   :members:

.. autoclass:: dns.cookie.Endpoint
   :members:

.. autoclass:: dns.cookie.CookieValidation
   :members:

.. autoclass:: dns.cookie.CookiePolicy
   :members:

.. autofunction:: dns.cookie.get_cookie_option
.. autofunction:: dns.cookie.set_cookie_option
.. autofunction:: dns.cookie.validation_for_message
.. autofunction:: dns.cookie.validate_udp_response
.. autoclass:: dns.cookie.CookieError
