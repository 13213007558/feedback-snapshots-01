"""Replay protection for signed Interests handled by :class:`ndn.app.NDNApp`.

The guard is meant to be composed with an authentication validator::

    guard = ReplayGuard(max_age=30_000)
    authenticate = HmacChecker.from_key('/control/key', key)

    @guard.route(app, '/control', authenticate)
    def on_control(name, app_param, reply, context):
        ...

Authentication (signature validity and signer identity) belongs to the
validator passed to :meth:`ReplayGuard.validator`.  Replay protection belongs
to this module.  Business idempotency for semantically equal but separately
signed requests remains an application concern.

Freshness is taken from the signed ``SignatureInfo`` fields, never from an
application parameter digest.  At least one of ``signature_time``,
``signature_seq_num`` and ``signature_nonce`` must be present.

* ``signature_time``: accepted when it lies in
  ``[now - max_age, now + max_clock_skew]``.  Its replay record expires when
  the timestamp itself becomes stale.  The record is paired with the full
  request name, so one signer may issue multiple requests in one millisecond;
  two byte-identical packets always collide.
* ``signature_seq_num``: tracked monotonically per authenticated signer.  A
  sequence number is accepted only if it is greater than the last committed
  sequence and is not currently in flight.
* ``signature_nonce``: tracked as an exact replay key for ``retention``
  milliseconds.

If several fields are present, all their rules are enforced.  A request is
identified by its full Interest name, which includes the
``ParametersSha256DigestComponent`` when ApplicationParameters are present,
together with the authenticated signer identity.  The digest is only a
request-context binding; it is not used as freshness.  ``signature_time`` is
therefore paired with the request: two different requests may share a
millisecond from one signer, while a byte-identical replay is rejected.

``commit`` means the handler returned normally.  It is not a claim that a
long-running action finished; applications that offload work to a task must
deduplicate that work themselves.

Completed records and sequence state are bounded by ``retention`` and by
``max_entries`` / ``max_signers``.  When the bounds are exhausted, new
requests are rejected rather than evicting unexpired replay state.  For a
nonce-only or sequence-only signer there is no signed absolute time, so
``retention`` is the replay horizon: it must be longer than any time during
which an old packet could still be accepted by the application.
"""

from __future__ import annotations

import asyncio as aio
import dataclasses as dc
import enum
import logging
from collections import OrderedDict
from hashlib import sha256
from typing import Any, Awaitable, Callable

from .. import encoding as enc
from .. import types
from ..encoding import ndn_format_0_3 as fmt
from ..utils import timestamp as _default_timestamp


Validator = Callable[
    [enc.FormalName, fmt.SignaturePtrs, dict[str, Any]],
    Awaitable[types.ValidResult],
]
ReplyFunc = Callable[[enc.BinaryStr], bool]
IntHandler = Callable[
    [enc.FormalName, enc.BinaryStr | None, ReplyFunc, dict[str, Any]],
    None,
]
SignerId = Any
RequestId = bytes


class _EntryState(enum.Enum):
    IN_PROGRESS = 0
    COMPLETED = 1


@dc.dataclass
class _Entry:
    expires_at: int
    state: _EntryState = _EntryState.IN_PROGRESS


@dc.dataclass
class _SeqState:
    last_seq: int = -1
    pending: set[int] = dc.field(default_factory=set)
    expires_at: int = 0


class ReplayToken:
    """A reservation created by :class:`ReplayGuard`.

    ``commit`` records that the handler returned normally.  ``abort`` removes
    the reservation so the same request can be retried.  A token is closed
    after either operation.
    """

    __slots__ = ('_guard', '_exact_keys', '_seq_claims', '_closed')

    def __init__(self, guard: 'ReplayGuard', exact_keys: list[Any],
                 seq_claims: list[tuple[SignerId, int]]):
        self._guard = guard
        self._exact_keys = exact_keys
        self._seq_claims = seq_claims
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def commit(self) -> bool:
        if self._closed:
            return False
        self._closed = True
        self._guard._commit(self)
        return True

    def abort(self) -> bool:
        if self._closed:
            return False
        self._closed = True
        self._guard._abort(self)
        return True

    def abort_if_open(self) -> bool:
        return self.abort() if not self._closed else False


class ReplayGuard:
    """Bounded replay guard for authenticated signed Interests."""

    CONTEXT_KEY = 'replay_token'

    def __init__(
        self,
        *,
        max_age: int = 60_000,
        max_clock_skew: int = 5_000,
        retention: int | None = None,
        max_entries: int = 4096,
        max_signers: int = 1024,
        clock: Callable[[], int] | None = None,
    ):
        if max_age <= 0:
            raise ValueError('max_age must be positive')
        if max_clock_skew < 0:
            raise ValueError('max_clock_skew must not be negative')
        if retention is not None and retention <= 0:
            raise ValueError('retention must be positive')
        if max_entries <= 0:
            raise ValueError('max_entries must be positive')
        if max_signers <= 0:
            raise ValueError('max_signers must be positive')

        self.max_age = max_age
        self.max_clock_skew = max_clock_skew
        self.retention = retention if retention is not None else max_age + max_clock_skew
        self.max_entries = max_entries
        self.max_signers = max_signers
        self._clock = clock if clock is not None else _default_timestamp
        self._entries: OrderedDict[Any, _Entry] = OrderedDict()
        self._seq: OrderedDict[SignerId, _SeqState] = OrderedDict()
        self._logger = logging.getLogger(__name__)

    def __len__(self) -> int:
        self._purge(self._clock())
        return len(self._entries) + len(self._seq)

    @property
    def record_count(self) -> int:
        self._purge(self._clock())
        return len(self._entries)

    def validator(
        self,
        authenticate: Validator,
        *,
        signer_id: Callable[[fmt.SignaturePtrs, dict[str, Any]], SignerId] | None = None,
        request_id: Callable[[enc.FormalName, fmt.SignaturePtrs, dict[str, Any]], RequestId] | None = None,
    ) -> Validator:
        """Compose authentication with replay reservation.

        ``authenticate`` runs first.  No replay state is touched unless it
        returns ``PASS`` or ``ALLOW_BYPASS``.  On success the reservation is
        placed in ``context[ReplayGuard.CONTEXT_KEY]`` for :meth:`protect`.
        """

        async def validate(name: enc.FormalName, sig: fmt.SignaturePtrs,
                           context: dict[str, Any]) -> types.ValidResult:
            result = await authenticate(name, sig, context)
            if result not in (types.ValidResult.PASS, types.ValidResult.ALLOW_BYPASS):
                return result
            token = self._reserve(
                name,
                sig,
                signer_id=signer_id,
                request_id=request_id,
                context=context,
            )
            if token is None:
                self._logger.warning('Replay rejected: %s', enc.Name.to_str(name))
                return types.ValidResult.FAIL
            context[self.CONTEXT_KEY] = token
            self._watch_current_task(token)
            return types.ValidResult.PASS

        return validate

    def protect(self, handler: IntHandler) -> IntHandler:
        """Wrap a route handler so reservations are committed only on success.

        A normal return commits the replay record.  An exception, including
        task cancellation, aborts it.  A missing reservation fails closed.
        """

        def protected(name: enc.FormalName, app_param: enc.BinaryStr | None,
                      reply: ReplyFunc, context: dict[str, Any]):
            token = context.get(self.CONTEXT_KEY)
            if not isinstance(token, ReplayToken) or token.closed:
                self._logger.warning('Missing replay token: %s', enc.Name.to_str(name))
                return None
            try:
                result = handler(name, app_param, reply, context)
            except BaseException:
                token.abort()
                raise
            token.commit()
            return result

        return protected

    def route(self, app: Any, name: enc.NonStrictName, authenticate: Validator):
        """Register a protected route on *app*.  Returns a decorator."""

        def decorator(handler: IntHandler) -> IntHandler:
            protected = self.protect(handler)
            return app.route(name, validator=self.validator(authenticate))(protected)

        return decorator

    def reserve(self, name: enc.FormalName, sig: fmt.SignaturePtrs, *,
                signer_id: SignerId | None = None,
                request_id: RequestId | None = None) -> ReplayToken | None:
        """Reserve a request directly, without a route validator.

        ``name`` must be the full Interest name, including the
        ``ParametersSha256DigestComponent`` when ApplicationParameters are
        present.  The name is the request identity; ``signature_time`` is a
        freshness bound and is deliberately not part of that identity.
        """
        if signer_id is None:
            resolved_signer = self._default_signer_id(sig)
        else:
            resolved_signer = signer_id
        if request_id is None:
            resolved_request = self._default_request_id(name)
        else:
            resolved_request = request_id
        return self._reserve_ids(sig, resolved_signer, resolved_request)

    def _reserve(self, name: enc.FormalName, sig: fmt.SignaturePtrs, *,
                 signer_id: Callable[[fmt.SignaturePtrs, dict[str, Any]], SignerId] | None,
                 request_id: Callable[[enc.FormalName, fmt.SignaturePtrs, dict[str, Any]], RequestId] | None,
                 context: dict[str, Any] | None) -> ReplayToken | None:
        resolved_signer = (signer_id(sig, context or {})
                           if signer_id is not None else self._default_signer_id(sig))
        resolved_request = (request_id(name, sig, context or {})
                            if request_id is not None
                            else self._default_request_id(name))
        return self._reserve_ids(sig, resolved_signer, resolved_request)

    def _reserve_ids(self, sig: fmt.SignaturePtrs,
                     signer: SignerId, request: RequestId) -> ReplayToken | None:
        info = sig.signature_info
        if info is None or signer is None:
            return None

        now = self._clock()
        self._purge(now)

        sig_time = info.signature_time
        sig_seq = info.signature_seq_num
        sig_nonce = info.signature_nonce

        if sig_time is None and sig_seq is None and sig_nonce is None:
            return None
        if sig_time is not None:
            if sig_time < now - self.max_age or sig_time > now + self.max_clock_skew:
                return None

        exact_keys: list[Any] = []
        if sig_time is not None:
            exact_keys.append(('time', signer, request, sig_time))
        if sig_nonce is not None:
            # A signature nonce is unique per signer, not per request.
            exact_keys.append(('nonce', signer, sig_nonce))

        for key in exact_keys:
            if key in self._entries:
                return None

        seq_state = self._seq.get(signer) if sig_seq is not None else None
        if seq_state is not None:
            if sig_seq <= seq_state.last_seq:
                return None
            if sig_seq in seq_state.pending:
                return None

        if len(self._entries) + len(exact_keys) > self.max_entries:
            return None
        if sig_seq is not None and seq_state is None and len(self._seq) >= self.max_signers:
            return None

        for key in exact_keys:
            expires_at = (sig_time + self.max_age + 1
                          if key[0] == 'time' else now + self.retention)
            entry = _Entry(expires_at=max(expires_at, now + 1))
            self._entries[key] = entry

        seq_claims: list[tuple[SignerId, int]] = []
        if sig_seq is not None:
            if seq_state is None:
                seq_state = _SeqState(expires_at=now + self.retention)
                self._seq[signer] = seq_state
            seq_state.pending.add(sig_seq)
            seq_state.expires_at = max(seq_state.expires_at, now + self.retention)
            self._seq.move_to_end(signer)
            seq_claims.append((signer, sig_seq))

        return ReplayToken(self, exact_keys, seq_claims)

    def _commit(self, token: ReplayToken) -> None:
        now = self._clock()
        for key in token._exact_keys:
            entry = self._entries.get(key)
            if entry is None:
                entry = _Entry(expires_at=now + self.retention)
                self._entries[key] = entry
            entry.state = _EntryState.COMPLETED
            if key[0] != 'time':
                # A timestamped record is bounded by the signature time;
                # extending it would admit replays after the time is stale.
                entry.expires_at = max(entry.expires_at, now + self.retention)
            self._entries.move_to_end(key)

        for signer, seq in token._seq_claims:
            state = self._seq.get(signer)
            if state is None:
                state = _SeqState(expires_at=now + self.retention)
                self._seq[signer] = state
            state.pending.discard(seq)
            if seq > state.last_seq:
                state.last_seq = seq
            state.expires_at = max(state.expires_at, now + self.retention)
            self._seq.move_to_end(signer)

    def _abort(self, token: ReplayToken) -> None:
        for key in token._exact_keys:
            self._entries.pop(key, None)

        now = self._clock()
        for signer, seq in token._seq_claims:
            state = self._seq.get(signer)
            if state is None:
                continue
            state.pending.discard(seq)
            state.expires_at = max(state.expires_at, now + self.retention)
            if state.last_seq < 0 and not state.pending:
                del self._seq[signer]
            else:
                self._seq.move_to_end(signer)

    def _watch_current_task(self, token: ReplayToken) -> None:
        try:
            task = aio.current_task()
        except RuntimeError:
            return
        if task is not None:
            task.add_done_callback(lambda _task: token.abort_if_open())

    def _purge(self, now: int) -> None:
        for key in list(self._entries.keys()):
            entry = self._entries[key]
            # An in-progress reservation is released by its owning task on
            # completion or cancellation.  Its count is still bounded by
            # max_entries.
            if entry.state is _EntryState.COMPLETED and entry.expires_at <= now:
                del self._entries[key]
        for signer in list(self._seq.keys()):
            state = self._seq[signer]
            if state.expires_at <= now and not state.pending:
                del self._seq[signer]

    @staticmethod
    def _default_signer_id(sig: fmt.SignaturePtrs) -> SignerId | None:
        info = sig.signature_info
        if info is None:
            return None
        locator = info.key_locator
        if locator is None:
            return None
        if locator.name:
            return info.signature_type, enc.Name.to_bytes(locator.name)
        if locator.key_digest:
            return info.signature_type, b'digest:' + bytes(locator.key_digest)
        return None

    @staticmethod
    def _default_request_id(name: enc.FormalName) -> RequestId:
        return sha256(enc.Name.to_bytes(name)).digest()
