# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Header-first admission for streaming decryption of untrusted sources.

``StreamDecryptor`` parses the message header lazily: nothing is read when the
object is constructed, but accessing :attr:`StreamDecryptor.header` (or calling
``read()`` for the first time) invokes ``_prep_message``, which reads the header
and header authentication directly from ``source_stream``.  A caller that only
limits the number of plaintext bytes it asks ``StreamDecryptor.read`` for does
not bound how many ciphertext bytes the SDK pulls from the source: the first
body read consumes one whole frame (framed messages) or the whole body
(non-framed messages) before any plaintext is returned.

This module puts the control where every read passes: immediately below the
SDK, around the source stream.  ``admit_message_stream`` parses the header under
a hard byte budget and returns the same decryptor that was used for admission,
so subsequent reads are byte-for-byte the reads the SDK would have made
directly.

Safety boundary
---------------
Admission may consume exactly:

* the serialized header body,
* the header authentication block, and
* for non-framed messages only, the fixed IV + plaintext-length preamble
  (``algorithm.iv_len + 8`` bytes).

It never consumes body ciphertext, the body authentication tag, or the footer.
The first call to ``read()`` after admission is what crosses into the body, and
that read is bounded by the decryptor's ``max_body_length`` (frame size or
non-framed content length), not by this budget.

Why bounding the caller's ``read`` is not enough
------------------------------------------------
A limit inside the caller's loop only controls how much plaintext is requested.
The SDK's first ``read(b)`` still loads one complete frame (framed) or the whole
body (non-framed) from the source before returning ``b`` bytes, and
``StreamDecryptor`` reads the header itself as soon as ``header`` is touched.
Because the caller learns the message size only *after* those reads, a
per-call limit on ``read`` cannot bound source consumption.  The bound has to
sit on the source object, below every SDK read, which is what
:class:`AdmissionMeter` does.

Failure attribution
-------------------
* Gate layer: :class:`AdmissionBudgetExceeded` -- the gate refused a read.  The
  input was not exhausted and the message was not judged.
* SDK deserialization layer: :class:`aws_encryption_sdk.exceptions.SerializationError`
  -- the input ended early or was malformed while parsing the header.  The
  exception carries ``admission_bytes_consumed`` / ``admission_reads``.
* SDK admission layer: ``NotSupportedError``, ``UnknownIdentityError``,
  ``MaxEncryptedDataKeysExceeded``, ``CustomMaximumValueExceeded``,
  ``MasterKeyProviderError``, ``ActionNotAllowedError`` -- a complete header
  was parsed and rejected on policy or on declared sizes.
* Close layer: ``SerializationError("Footer not read")`` -- a state assertion
  from ``StreamDecryptor.close``; it reads nothing.  Use
  :func:`abandon_admitted_stream` when the caller abandons a message after
  admission.
"""
import copy
import io

import attr
from wrapt import ObjectProxy

from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.streaming_client import StreamDecryptor

#: Suggested admission budget.  Large enough for a header with a maximum-size
#: encryption context and a few encrypted data keys, small enough that a
#: hostile length field cannot force arbitrary reads before rejection.
DEFAULT_ADMISSION_BUDGET_BYTES = 128 * 1024


class AdmissionError(Exception):
    """Base class for failures raised by the admission gate itself.

    Deliberately *not* a subclass of
    :class:`aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError` so that
    callers cannot accidentally treat a gate decision as an SDK error.
    """


class AdmissionBudgetExceeded(AdmissionError):
    """The admission phase needed more source bytes than its budget allowed.

    This is the only exception raised by the gate layer.  It means the gate
    stopped the read; it does **not** mean the input ended.  The source may
    still hold more bytes.

    :param int budget_bytes: Configured admission budget.
    :param int consumed_bytes: Bytes actually read from the source so far.
    :param int requested_bytes: Size of the read that did not fit, or ``-1``
        for an unbounded read.
    """

    def __init__(self, budget_bytes, consumed_bytes, requested_bytes):
        """Prepares the exception and exposes its accounting."""
        self.budget_bytes = budget_bytes
        self.consumed_bytes = consumed_bytes
        self.requested_bytes = requested_bytes
        super(AdmissionBudgetExceeded, self).__init__(
            "admission budget exhausted: {consumed} of {budget} bytes consumed; "
            "next read requested {requested} bytes".format(
                consumed=consumed_bytes,
                budget=budget_bytes,
                requested=requested_bytes,
            )
        )


class AdmissionMeter(ObjectProxy):
    """Read-only, non-rewindable wrapper that meters and bounds source reads.

    While armed, every read is checked against the remaining budget *before*
    the underlying source is touched.  A request that does not fit raises
    :class:`AdmissionBudgetExceeded`, so the SDK can never turn a budget stop
    into a short read (and therefore into a misleading ``SerializationError``).

    ``seek``/``tell`` are blocked: the archive entry may receive a pipe that
    cannot be rewound, and a silent rewind would corrupt every later read.
    ``readline``/iteration are blocked as well so that no read path can bypass
    the meter.

    :param wrapped: Binary source stream.
    :param int budget_bytes: Maximum bytes the armed phase may consume.
    """

    def __init__(self, wrapped, budget_bytes):
        """Wraps the source and arms the budget."""
        super(AdmissionMeter, self).__init__(wrapped)
        self._self_budget_bytes = budget_bytes
        self._self_consumed_bytes = 0
        self._self_reads = []
        self._self_armed = True

    @property
    def budget_bytes(self):
        """Configured admission budget."""
        return self._self_budget_bytes

    @property
    def consumed_bytes(self):
        """Total bytes returned by the wrapped source so far."""
        return self._self_consumed_bytes

    @property
    def reads(self):
        """``(requested, returned)`` pairs, in call order."""
        return list(self._self_reads)

    @property
    def armed(self):
        """Whether the admission budget is still enforced."""
        return self._self_armed

    def disarm(self):
        """Lifts the budget after a successful admission."""
        self._self_armed = False

    def read(self, size=-1):
        """Reads from the source, enforcing the admission budget while armed."""
        if size is None:
            size = -1

        if self._self_armed:
            if size < 0:
                raise AdmissionBudgetExceeded(self._self_budget_bytes, self._self_consumed_bytes, size)
            remaining = self._self_budget_bytes - self._self_consumed_bytes
            if size > remaining:
                raise AdmissionBudgetExceeded(self._self_budget_bytes, self._self_consumed_bytes, size)

        payload = self.__wrapped__.read(size)
        if payload is None:
            # A non-blocking source signals "no data right now" with None.
            # Reporting that as b"" would look like EOF to the SDK and be
            # misattributed as truncated input, so fail at the gate instead.
            raise AdmissionError(
                "source returned no data without signalling end of stream; "
                "admission requires a blocking binary source"
            )
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(
                "admission sources must be binary; received {}".format(type(payload).__name__)
            )
        if size >= 0 and len(payload) > size:
            # A read returning more than requested breaks the budget invariant
            # and the SDK's framing math; fail loudly at the gate.
            raise AdmissionError(
                "source returned {returned} bytes for a {requested}-byte read".format(
                    returned=len(payload), requested=size
                )
            )

        self._self_consumed_bytes += len(payload)
        self._self_reads.append((size, len(payload)))
        return payload

    def read1(self, size=-1):
        """Metered equivalent of ``read1``; the SDK only needs ``read``."""
        return self.read(size)

    def readinto(self, buffer):
        """Metered ``readinto`` so aliases cannot bypass the budget."""
        payload = self.read(len(buffer))
        buffer[: len(payload)] = payload
        return len(payload)

    def readline(self, size=-1):
        """Refuses an unmetered line-read path."""
        raise io.UnsupportedOperation("admission meter does not support readline; use read")

    def readlines(self, hint=-1):
        """Refuses an unmetered line-read path."""
        raise io.UnsupportedOperation("admission meter does not support readlines; use read")

    def seek(self, offset, whence=0):
        """Blocks rewinding of the source."""
        raise io.UnsupportedOperation("admission meter must not rewind the source")

    def tell(self):
        """Blocks position probing that would imply a rewindable source."""
        raise io.UnsupportedOperation("admission meter does not expose a source position")

    def seekable(self):
        """The metered source is intentionally non-seekable."""
        return False

    def readable(self):
        """The metered source is readable."""
        return True

    def writable(self):
        """The metered source is read-only."""
        return False

    def write(self, data):
        """Blocks writes to the source."""
        raise io.UnsupportedOperation("admission meter is read-only")

    def __iter__(self):
        """Refuses an unmetered iteration path."""
        raise io.UnsupportedOperation("admission meter does not support iteration; use read")

    def __next__(self):
        """Refuses an unmetered iteration path."""
        raise io.UnsupportedOperation("admission meter does not support iteration; use read")

    def __enter__(self):
        """Returns the meter itself, never the unwrapped source."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Does not close the caller-owned source."""
        return False


@attr.s(frozen=True)
class AdmissionResult(object):
    """Successful admission.

    Use :attr:`decryptor` for all subsequent reads.  It is the same instance
    that parsed the header, over the same metered source, so no bytes are
    replayed and the output is identical to reading the original source
    directly.

    :ivar decryptor: Admitted :class:`StreamDecryptor`.
    :ivar header: Parsed :class:`aws_encryption_sdk.structures.MessageHeader`.
    :ivar meter: :class:`AdmissionMeter`; ``meter.reads`` and
        ``meter.consumed_bytes`` describe exactly what admission consumed.
    """

    decryptor = attr.ib()
    header = attr.ib()
    meter = attr.ib()

    @property
    def consumed_bytes(self):
        """Source bytes consumed during admission."""
        return self.meter.consumed_bytes

    @property
    def reads(self):
        """Read log for the admission phase."""
        return self.meter.reads


def _attach_diagnostics(error, meter):
    """Attaches admission accounting to an SDK exception without masking it."""
    try:
        error.admission_bytes_consumed = meter.consumed_bytes
        error.admission_reads = meter.reads
    except Exception:  # pragma: no cover - defensive for exotic exception types
        pass


def admit_message_stream(source, budget_bytes=DEFAULT_ADMISSION_BUDGET_BYTES, **decryptor_kwargs):
    """Parses and validates the message header before releasing the stream.

    The source is never rewound and never read past the header (plus the
    non-framed preamble).  On success the returned decryptor continues to read
    from the same source, so downstream behavior is unchanged.

    :param source: Binary, file-like source.  May be a non-seekable pipe.
    :param int budget_bytes: Hard cap on bytes consumed during admission.
    :param decryptor_kwargs: Forwarded to :class:`StreamDecryptor`
        (``key_provider``/``materials_manager``/``keyring``,
        ``max_body_length``, ``max_encrypted_data_keys``,
        ``commitment_policy``, ``signature_policy``, ...).
    :returns: :class:`AdmissionResult`
    :raises AdmissionBudgetExceeded: the gate stopped the read at its budget.
    :raises AdmissionError: the source is not a usable blocking binary stream.
    :raises aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError: the
        header was rejected or the input ended before a complete header.  SDK
        exceptions propagate unchanged and carry ``admission_bytes_consumed``
        and ``admission_reads`` attributes for diagnostics.
    """
    if budget_bytes is None or not isinstance(budget_bytes, int) or budget_bytes < 0:
        raise ValueError("budget_bytes must be a non-negative integer")
    if not callable(getattr(source, "read", None)):
        raise TypeError("source must be a binary file-like object with a read method")
    if "source" in decryptor_kwargs:
        raise TypeError("source is supplied by the admission gate; do not pass it in decryptor_kwargs")

    meter = AdmissionMeter(source, budget_bytes)
    if "config" in decryptor_kwargs:
        # ``StreamDecryptor`` ignores a ``source`` argument when a config object
        # is supplied, so the meter must be installed on the config instead.
        # ``copy.copy`` avoids re-running attrs post-init (which would reject a
        # config that already resolved its materials manager).
        config = decryptor_kwargs.pop("config")
        if decryptor_kwargs:
            raise TypeError("pass either config or individual decryptor arguments, not both")
        metered_config = copy.copy(config)
        metered_config.source = meter
        decryptor = StreamDecryptor(config=metered_config)
    else:
        decryptor = StreamDecryptor(source=meter, **decryptor_kwargs)
    try:
        header = decryptor.header
    except Exception as error:
        if not isinstance(error, AdmissionError):
            _attach_diagnostics(error, meter)
        raise
    meter.disarm()
    return AdmissionResult(decryptor=decryptor, header=header, meter=meter)


def abandon_admitted_stream(result):
    """Closes an admitted decryptor without reading any further body bytes.

    ``StreamDecryptor.close`` treats an unread footer as an error, which is
    correct for a partially consumed message but unhelpful when the caller has
    decided, immediately after admission, not to process the message at all.
    This helper releases the decryptor while leaving the caller-owned source
    open; it never reads from the source.

    :param AdmissionResult result: Value returned by :func:`admit_message_stream`.
    """
    io.IOBase.close(result.decryptor)


__all__ = (
    "abandon_admitted_stream",
    "AdmissionBudgetExceeded",
    "AdmissionError",
    "AdmissionMeter",
    "AdmissionResult",
    "DEFAULT_ADMISSION_BUDGET_BYTES",
    "admit_message_stream",
)
