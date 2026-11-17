.. _rpz:

DNS Response Policy Zones
=========================

:mod:`dns.rpz` is a small, *offline* interpreter for a limited subset of the
DNS Response Policy Zone (RPZ) mechanism.  It is intended for pre-rehearsing
which policy rules in a set of policy zones actually take effect for a given
name lookup or a given set of response addresses.  It never starts a name
server and never sends queries.

The supported feature set is deliberately bounded:

* **Triggers:** QNAME triggers (exact owners and the DNS-style leftmost-label
  wildcard) and response address triggers (``rpz-ip`` IPv4 and ``rpz-ip6``
  IPv6 prefixes).
* **Actions:** ``NXDOMAIN`` (including the legacy root-target CNAME form),
  ``NODATA`` and ``PASSTHRU``, expressed through CNAME action RRs.
* **Rule selection:** longest-match specificity within a policy zone, then
  the configured order of the policy zones, which is treated as trusted
  configuration.  A QNAME rule always outranks a response-address rule,
  matching the order in which a resolver applies policy.

Everything outside this scope is retained rather than guessed.  NSDNAME and
NSIP triggers, wildcard address triggers, QNAME-redirect/local-data style
actions (including the legacy DROP form), non-CNAME action RRs and unknown
action names are reported as *pending*.  Pending items are matched against
each probe and surfaced in the evaluation, so a rule whose semantics are not
interpreted here can never silently look like a miss.

Synthetic answers are generated only from policy data and never set the AA
bit, so they cannot be confused with authoritative data of the original zone.

The mechanism is defined in the RPZ specification
`draft-ietf-dnsop-dns-rpz <https://datatracker.ietf.org/doc/draft-ietf-dnsop-dns-rpz/>`_
and implemented in BIND.

.. automodule:: dns.rpz
   :members:
   :member-order: groupwise
