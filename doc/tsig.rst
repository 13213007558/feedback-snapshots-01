.. module:: dns.tsig
.. _tsig:

TSIG
====

Dnspython supports TSIG (RFC 8945) signing and validation.  This chapter
describes a security-relevant part of that support: deciding what a TSIG
error response actually proves.

What a TSIG signature covers
----------------------------

A TSIG MAC is computed over, in order:

* the request MAC, if any, prefixed with its two-octet length;
* the message, with the TSIG RR removed and the ARCOUNT decremented, and
  with the DNS header ID replaced by the TSIG Original ID;
* the key name and class (ANY);
* the TSIG TTL (zero);
* the algorithm name;
* Time Signed, Fudge, Error, and Other Data lengths and values.

Consequently, once the MAC has been verified with the local key *and* the
request MAC of the request being answered, the following fields are
authenticated:

``algorithm``, ``time_signed``, ``fudge``, ``original_id``, ``error``,
``other``, and the key name, as well as the entire DNS message body.

The MAC is the authenticator.  The dns.tsig module also requires the TSIG
owner name to equal the local key's name and the TSIG algorithm to equal
the local key's algorithm before it computes the MAC, so a response cannot
switch to another configured key or algorithm.

Error responses and their MACs
------------------------------

RFC 8945 defines two relevant cases:

* BADTIME and other errors a server can only report after it has
  authenticated the request are sent with a normal MAC computed with the
  shared key, and BADTIME carries the server's current time in Other Data
  as a 48-bit unsigned integer.
* BADSIG, BADKEY, and BADTRUNC are normally sent with an empty MAC,
  because the server could not or would not authenticate the request.

The second case means the error code is only a claim by whoever sent the
packet.  It is still useful operationally, but it must not be used to
change a clock, a signing time, or a retry policy.  BADTIME must carry a
MAC; a BADTIME response with an empty MAC is rejected as
``BadSignature``, not reported as ``PeerBadTime``, so existing code that
treats ``PeerBadTime`` as a trustworthy hint cannot be fooled by an
unsigned packet.

For BADTIME the server's time is in Other Data, not in Time Signed.  Time
Signed is the value the client put in its request.  Reading the server's
time from Time Signed, or adopting the request's own Time Signed as "server
time", would make the client agree with itself and never correct anything.

Error classes in dns.tsig
-------------------------

``BadTime``
    Raised by :func:`dns.tsig.validate` when the MAC verified but Time
    Signed is outside the local clock's Fudge window.  The peer did not
    report an error; this is a local validation result.  ``authenticated``
    is true because the MAC verified, and ``evidence.server_time`` is the
    authenticated Time Signed value.  ``evidence.error`` is zero, which
    distinguishes this case from a peer report.  ``PeerBadTime`` is *not*
    raised in this case.

``PeerBadTime``
    Raised when the response's TSIG Error field is BADTIME.  Check
    ``authenticated``.  When true, the response MAC verified with this
    key and request MAC, and ``server_time`` is the server's time from
    Other Data.  When false, it is only an unauthenticated claim.

``PeerBadKey``, ``PeerBadSignature``, ``PeerBadTruncation``
    Peer reports which RFC 8945 normally sends with an empty MAC, so
    ``authenticated`` is normally false.  If a peer does send a non-empty
    MAC and it verifies, the report is marked authenticated; the error code
    was then covered by the MAC.

``BadSignature``
    The MAC did not verify, or a TSIG error other than BADSIG, BADKEY, and
    BADTRUNC had no MAC.  All TSIG fields, including Error and Other Data,
    are untrusted.  A forged or unsigned BADTIME ends up here, not in
    ``PeerBadTime``.

``BadKey``, ``BadAlgorithm``
    The response's owner name or algorithm does not match the local key.
    These checks happen before the MAC is computed.

``dns.message.MissingTSIG``
    A response to a TSIG-signed request had no TSIG at all.

A response to a signed request with no TSIG is rejected by
:func:`dns.message.from_wire` before any application code sees it.

Assessing a response
--------------------

:func:`dns.tsig.assess_tsig_response` performs a non-raising check of a
parsed response against the original query:

.. code-block:: python

   assessment = dns.tsig.assess_tsig_response(query, response)
   if assessment.status is dns.tsig.TSIGResponseStatus.PEER_BAD_TIME:
       if assessment.authenticated and assessment.server_time is not None:
           ...  # authenticated server time

The checks are ordered so that no unauthenticated field can influence the
result:

1. the query is TSIG-signed;
2. the response matches the query's id, opcode, and question
   (:meth:`dns.message.Message.is_response`);
3. the response has a TSIG;
4. the response's key name and algorithm equal the query's;
5. the response was validated with this query's request MAC;
6. the response MAC verifies with the query's key and request MAC;
7. only now are Error, Other Data, and Time Signed interpreted.

The three binding flags on the assessment say exactly which of these hold:
``transaction_bound`` (step 2), ``request_mac_bound`` (step 5), and
``authenticated`` (steps 4 and 6).  ``server_time`` is non-``None`` only
when the MAC verified and all three flags are true.  For a MAC-covered
BADTIME it is the server time from Other Data (``time_source`` is
``"other"``); for a local ``BadTime`` it is the authenticated Time Signed
of a NOERROR response (``time_source`` is ``"time_signed"``), which the
retry policy still treats as ``CHECK_LOCAL_CLOCK``.

:func:`dns.tsig.assess_tsig_error` does the same for the exception path.
It uses the decoded message attached by :func:`dns.message.from_wire` to
exceptions it raises, or falls back to the MAC-covered Original ID.

Retry policy
------------

:func:`dns.tsig.decide_tsig_retry` maps an assessment to one of:

``NONE``
    Do not retry.  Used for unauthenticated errors, MAC failures, missing
    signatures, wrong transactions, and exhausted retry budgets.

``CHECK_LOCAL_CLOCK``
    A local ``BadTime`` occurred, or an authenticated BADTIME had no usable
    server time or implied an offset larger than the policy allows.  An
    operator should check the local clock.  The library does not change it.

``RETRY_WITH_TIME_OFFSET``
    An authenticated, request-bound, transaction-bound BADTIME with a
    server time inside ``TSIGRetryPolicy.max_offset``.  The decision carries
    ``signing_time_offset``; assign it to the retry message's
    ``tsig_time_offset`` attribute.  This changes only the Time Signed of
    that message.  It does not change the system clock and does not change
    Fudge.

The default policy allows one retry and a 300-second offset.  A client
should also treat the retry as a new transaction for logging and rate
limiting, and must not retry more than the policy allows.

Nothing in dns.tsig changes the system clock, and no error object contains
the shared secret.  Error records contain the key name, the algorithm, the
Original ID, Time Signed, Fudge, Error, Other Data, and a hash of the
request MAC; they never contain ``Key.secret``.

A complete offline demonstration is in ``examples/tsig_badtime.py``.  It
builds a normal response, an authenticated BADTIME, a forged BADTIME, and
an unsigned BADTIME locally, and prints the resulting exception, status,
and retry decision.

API reference
-------------

.. autoclass:: dns.tsig.TSIGErrorInfo
   :members:

.. autoexception:: dns.tsig.BadTime
.. autoexception:: dns.tsig.BadSignature
.. autoexception:: dns.tsig.BadKey
.. autoexception:: dns.tsig.BadAlgorithm
.. autoexception:: dns.tsig.PeerError
.. autoexception:: dns.tsig.PeerBadTime
.. autoexception:: dns.tsig.PeerBadKey
.. autoexception:: dns.tsig.PeerBadSignature
.. autoexception:: dns.tsig.PeerBadTruncation

.. autoclass:: dns.tsig.TSIGResponseStatus
   :members:
.. autoclass:: dns.tsig.TSIGResponseAssessment
   :members:
.. autoclass:: dns.tsig.TSIGRetryAction
   :members:
.. autoclass:: dns.tsig.TSIGRetryPolicy
   :members:
.. autoclass:: dns.tsig.TSIGRetryDecision
   :members:

.. autofunction:: dns.tsig.assess_tsig_response
.. autofunction:: dns.tsig.assess_tsig_error
.. autofunction:: dns.tsig.decide_tsig_retry
