:mod:`ndn.app` package
======================

Introduction
------------

The :mod:`ndn.app` package contains :class:`NDNApp`, the canonical asyncio
application API. It connects to an NDN forwarder and provides:

* Interest expression and Data validation.
* Interest handlers with PIT-token-aware reply callbacks.
* Prefix registration and unregistration.
* Signed NFD management commands.

Consumer code calls :meth:`NDNApp.express` and receives ``(name, content,
context)``. The context contains parsed metadata, signature pointers, the raw
packet, and the deadline. Producer handlers receive ``(name, app_param, reply,
context)`` and should send encoded Data through ``reply`` so PIT tokens are
preserved.

The application does not own a keychain. Use :meth:`NDNApp.default_keychain`
when the default client configuration is desired, and pass an explicit signer
to :meth:`NDNApp.express` or :meth:`NDNApp.make_data`.

Signed Interest Replay Protection
---------------------------------

A passing signature check proves who signed an Interest, not that the Interest
is new.  :class:`ndn.app_support.replay_guard.ReplayGuard` adds the second half
and is designed to wrap a route handler::

    from ndn.app_support.replay_guard import ReplayGuard
    from ndn.security import HmacChecker

    guard = ReplayGuard(max_age=30_000)
    authenticate = HmacChecker.from_key('/control/KEY/a', key)

    @guard.route(app, '/control', authenticate)
    def on_control(name, app_param, reply, context):
        ...

The guard runs after *authenticate* and before the handler.  It takes freshness
from the signed ``SignatureInfo`` fields only: ``signature_time`` must be within
``[now - max_age, now + max_clock_skew]``, ``signature_seq_num`` must strictly
increase per authenticated signer, and ``signature_nonce`` is one-time per
signer.  An Interest with none of these fields is rejected.  The request
context, including the ParametersSha256DigestComponent, only binds a request to
its replay key; a digest by itself is never treated as freshness.

Parallel copies of one Interest admit exactly one handler execution because the
replay record is reserved while validation completes.  A normal handler return
marks the action completed; an exception, task cancellation, or failed
authentication leaves no completed record, so a retry is possible.  Records and
sequence state are bounded by ``retention``, ``max_entries``, and
``max_signers``; when a bound is reached the guard rejects new requests instead
of evicting unexpired replay state.

Authentication and business idempotency are separate concerns.  The validator
decides whether the signature and signer are acceptable.  The guard decides
whether this signed request was already admitted.  Two requests that are
semantically equivalent but signed separately (different timestamps, sequence
numbers, or nonces) are still the application's responsibility to deduplicate.

Reference
---------

.. automodule:: ndn.app
    :members:

.. automodule:: ndn.app_support.replay_guard
    :members: ReplayGuard, ReplayToken
